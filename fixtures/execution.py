"""Disposable file and loopback TCP resources for execution verification."""

from __future__ import annotations

import ipaddress
import socket
import tempfile
import threading
from collections.abc import Mapping
from contextlib import ExitStack
from pathlib import Path
from types import TracebackType

from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity
from confined_tool_execution.policy import calculate_argument_digest, validate_capability

OUTSIDE_CONTENT = "generated outside-workspace reference record\n"
RESOURCE_RESPONSE = b"reference response\n"


class LoopbackResource:
    """One bounded fixture listener that cannot bind a public interface."""

    def __init__(self, host: str, port: int = 0) -> None:
        address = ipaddress.IPv4Address(host)
        if not address.is_loopback or str(address) != host:
            raise ValueError("fixture listeners require canonical IPv4 loopback addresses")
        self.host = host
        self.port = port
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.settimeout(0.1)
        self._condition = threading.Condition()
        self._stopped = threading.Event()
        self._connections = 0
        self._failure: OSError | None = None
        self._thread = threading.Thread(
            target=self._serve, name="reference_resource_listener", daemon=True
        )

    def __enter__(self) -> LoopbackResource:
        try:
            self._listener.bind((self.host, self.port))
            self.port = int(self._listener.getsockname()[1])
            self._listener.listen(8)
            self._thread.start()
        except BaseException:
            self._listener.close()
            raise
        return self

    def _serve(self) -> None:
        while not self._stopped.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError as error:
                if not self._stopped.is_set():
                    self._failure = error
                return
            with connection:
                with self._condition:
                    self._connections += 1
                    self._condition.notify_all()
                connection.settimeout(0.5)
                try:
                    connection.sendall(RESOURCE_RESPONSE)
                except (BrokenPipeError, ConnectionResetError, TimeoutError):
                    # A connect-only handler may close before reading the response.
                    pass

    @property
    def connection_count(self) -> int:
        with self._condition:
            return self._connections

    def wait_for_connections(self, count: int, timeout: float = 2.0) -> bool:
        with self._condition:
            return self._condition.wait_for(lambda: self._connections >= count, timeout=timeout)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stopped.set()
        self._listener.close()
        self._thread.join(timeout=2)
        if exception_type is None and self._failure is not None:
            raise self._failure
        if self._thread.is_alive():
            raise RuntimeError("reference listener did not terminate within its bound")


class ExecutionFixture:
    """Own generated workspace data and exactly two loopback listeners."""

    def __init__(self, *, other_host: str = "127.0.0.1", same_audience_port: bool = False) -> None:
        if same_audience_port and other_host == "127.0.0.1":
            raise ValueError("same-port verification requires a different loopback address")
        self.other_host = other_host
        self.same_audience_port = same_audience_port
        self.identity = ExecutionIdentity("principal.reference", "capability.reference")
        self.workspace: Path
        self.outside_path: Path
        self.arguments: dict[str, str]
        self.audience_listener: LoopbackResource
        self.other_listener: LoopbackResource
        self._resources: ExitStack

    def __enter__(self) -> ExecutionFixture:
        self._resources = ExitStack()
        try:
            directory = self._resources.enter_context(
                tempfile.TemporaryDirectory(prefix="confined_execution_")
            )
            root = Path(directory).resolve()
            self.workspace = root / "workspace"
            self.workspace.mkdir(mode=0o700)
            self.outside_path = root / "outside_record.txt"
            self.outside_path.write_text(OUTSIDE_CONTENT, encoding="utf-8")
            self.audience_listener = self._resources.enter_context(LoopbackResource("127.0.0.1"))
            other_port = self.audience_listener.port if self.same_audience_port else 0
            self.other_listener = self._resources.enter_context(
                LoopbackResource(self.other_host, other_port)
            )
            self.arguments = {
                "outside_path": str(self.outside_path),
                "other_host": self.other_listener.host,
                "other_port": str(self.other_listener.port),
                "output_name": "record.txt",
                "metadata_probe": "no",
                "execution_probe": "no",
            }
        except BaseException:
            self._resources.close()
            raise
        return self

    def capability(self, arguments: Mapping[str, str] | None = None) -> CapabilityRecord:
        selected_arguments = self.arguments if arguments is None else arguments
        record = CapabilityRecord(
            audience_host=self.audience_listener.host,
            audience_port=self.audience_listener.port,
            workspace=self.workspace,
            tool_name="workspace.reference",
            argument_digest=calculate_argument_digest(selected_arguments),
        )
        validate_capability(record, selected_arguments)
        return record

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._resources.__exit__(exception_type, exception, traceback)
