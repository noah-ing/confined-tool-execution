"""Mediate one initialized child without continuing pointer-bearing syscalls."""

import array
import ctypes
import errno
import io
import json
import os
import selectors
import socket
import stat
import struct

# A fixed isolated interpreter is launched without a shell.
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from typing import Any, TextIO

from confined_tool_execution.handler import validate_handler_arguments
from confined_tool_execution.linux import (
    ConfinementUnavailable,
    Notification,
    copy_process_bytes,
    copy_process_string,
    duplicate_process_descriptor,
    get_notification,
    inject_descriptor,
    load_kernel_support,
    notification_valid,
    open_workspace_descriptor,
    send_notification_result,
)
from confined_tool_execution.models import (
    CapabilityRecord,
    DenialRecord,
    ExecutionIdentity,
    ExecutionResult,
)
from confined_tool_execution.policy import (
    PolicyViolation,
    build_child_environment,
    calculate_argument_digest,
    validate_audience,
    validate_capability,
    validate_identity,
    workspace_relative_path,
)
from confined_tool_execution.records import emit_denial_record

MAXIMUM_REPORT_BYTES = 65536
MAXIMUM_EXECUTION_SECONDS = 10
MAXIMUM_NOTIFICATIONS = 64


def _open_arguments(notification: Notification) -> tuple[str, int, int, int]:
    arguments = notification.arguments
    if notification.syscall_name == "open":
        address, flags, mode = arguments[:3]
        directory = -100
    elif notification.syscall_name == "creat":
        address, mode = arguments[:2]
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        directory = -100
    elif notification.syscall_name == "openat":
        directory = ctypes.c_int32(arguments[0]).value
        address, flags, mode = arguments[1:4]
    else:
        directory = ctypes.c_int32(arguments[0]).value
        address = arguments[1]
        if arguments[3] != 24:
            raise OSError(errno.EINVAL, "unsupported_openat2_structure")
        attributes = copy_process_bytes(notification.process_id, arguments[2], 24)
        flags, mode, resolution = struct.unpack("=QQQ", attributes)
        if resolution:
            raise OSError(errno.EINVAL, "caller_resolution_flags_not_supported")
    path = copy_process_string(notification.process_id, address)
    if notification.syscall_name != "openat2":
        flags &= 0xFFFFFFFF
        mode &= 0xFFFFFFFF
    return path, directory, flags, mode


def _open_permitted_file(
    workspace_descriptor: int, relative_path: str, flags: int, mode: int
) -> int:
    permitted = (
        os.O_ACCMODE
        | os.O_CREAT
        | os.O_EXCL
        | os.O_TRUNC
        | os.O_APPEND
        | os.O_CLOEXEC
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    access = flags & os.O_ACCMODE
    if flags & ~permitted or access not in {os.O_RDONLY, os.O_WRONLY, os.O_RDWR}:
        raise OSError(errno.EACCES, "unsupported_open_flags")
    if flags & os.O_TRUNC and access == os.O_RDONLY:
        raise OSError(errno.EACCES, "truncation_requires_write_access")
    if mode & ~0o777:
        raise OSError(errno.EACCES, "unsupported_creation_mode")
    # Inspect an existing object without invoking a device's open operation.
    # The trusted workspace must not be concurrently mutated by another actor.
    try:
        inspection_descriptor = open_workspace_descriptor(
            workspace_descriptor, relative_path, os.O_PATH, 0
        )
    except FileNotFoundError:
        if not flags & os.O_CREAT:
            raise
    else:
        try:
            attributes = os.fstat(inspection_descriptor)
            if not stat.S_ISREG(attributes.st_mode) and not (
                stat.S_ISDIR(attributes.st_mode) and access == os.O_RDONLY
            ):
                raise OSError(errno.EACCES, "unsupported_workspace_object_type")
            if attributes.st_uid != os.geteuid() or (
                stat.S_ISREG(attributes.st_mode) and attributes.st_nlink != 1
            ):
                raise OSError(errno.EACCES, "workspace_object_is_not_exclusively_owned")
        finally:
            os.close(inspection_descriptor)
    descriptor = open_workspace_descriptor(
        workspace_descriptor, relative_path, flags, (mode & 0o600) if flags & os.O_CREAT else 0
    )
    try:
        attributes = os.fstat(descriptor)
        if attributes.st_uid != os.geteuid():
            raise OSError(errno.EACCES, "workspace_object_has_different_owner")
        regular = stat.S_ISREG(attributes.st_mode)
        directory = stat.S_ISDIR(attributes.st_mode)
        if not regular and not (directory and access == os.O_RDONLY):
            raise OSError(errno.EACCES, "unsupported_workspace_object_type")
        if regular and attributes.st_nlink != 1:
            raise OSError(errno.EACCES, "multiply_linked_workspace_file")
        if flags & os.O_TRUNC:
            if not regular:
                raise OSError(errno.EACCES, "only_regular_files_may_be_truncated")
            os.ftruncate(descriptor, 0)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _NotificationSupervisor:
    def __init__(
        self,
        capability: CapabilityRecord,
        identity: ExecutionIdentity,
        workspace_descriptor: int,
        process_descriptor: int,
        child_process_id: int,
        listener_descriptor: int,
        output: TextIO,
    ) -> None:
        self.capability = capability
        self.identity = identity
        self.workspace_descriptor = workspace_descriptor
        self.process_descriptor = process_descriptor
        self.child_process_id = child_process_id
        self.listener_descriptor = listener_descriptor
        self.output = output
        self.denials: list[DenialRecord] = []
        self.notification_count = 0

    def _connect(self, notification: Notification, host: str, port: int) -> None:
        validate_audience(host, port)
        if (host, port) != (self.capability.audience_host, self.capability.audience_port):
            raise PolicyViolation("request_endpoint_does_not_match_capability")
        descriptor = duplicate_process_descriptor(
            self.process_descriptor, ctypes.c_int32(notification.arguments[0]).value
        )
        try:
            connection = socket.socket(fileno=descriptor)
        except BaseException:
            os.close(descriptor)
            raise
        with connection:
            if (
                connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) != socket.AF_INET
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL)
                != socket.IPPROTO_TCP
            ):
                raise OSError(errno.EACCES, "only_ipv4_tcp_sockets_are_permitted")
            if not notification_valid(self.listener_descriptor, notification.identifier):
                raise OSError(errno.ENOENT, "notification_no_longer_valid")
            connection.settimeout(2)
            try:
                connection.connect((self.capability.audience_host, self.capability.audience_port))
            finally:
                # Both descriptors refer to the same open file description.
                connection.setblocking(True)

    def mediate(self, notification: Notification) -> None:
        self.notification_count += 1
        if self.notification_count > MAXIMUM_NOTIFICATIONS:
            raise RuntimeError("notification_limit_exceeded")
        if notification.process_id != self.child_process_id:
            raise RuntimeError("notification_from_unregistered_process")
        if not notification_valid(self.listener_descriptor, notification.identifier):
            return
        operation = (
            "connect"
            if notification.syscall_name == "connect"
            else "exec"
            if notification.syscall_name in {"execve", "execveat"}
            else "open"
        )
        target = "unreadable_request"
        try:
            if operation == "open":
                target, directory, flags, mode = _open_arguments(notification)
                relative = workspace_relative_path(self.capability.workspace, target, directory)
                if not notification_valid(self.listener_descriptor, notification.identifier):
                    return
                descriptor = _open_permitted_file(self.workspace_descriptor, relative, flags, mode)
                try:
                    inject_descriptor(self.listener_descriptor, notification.identifier, descriptor)
                finally:
                    os.close(descriptor)
                return
            if operation == "exec":
                address_index = 1 if notification.syscall_name == "execveat" else 0
                target = copy_process_string(
                    notification.process_id, notification.arguments[address_index]
                )
                raise PolicyViolation("new_execution_is_not_permitted")
            if notification.arguments[2] != 16:
                raise OSError(errno.EACCES, "only_ipv4_socket_addresses_are_permitted")
            address = copy_process_bytes(notification.process_id, notification.arguments[1], 16)
            if int.from_bytes(address[:2], sys.byteorder) != socket.AF_INET:
                raise OSError(errno.EACCES, "only_ipv4_socket_addresses_are_permitted")
            host = socket.inet_ntop(socket.AF_INET, address[4:8])
            port = int.from_bytes(address[2:4], "big")
            target = f"{host}:{port}"
            self._connect(notification, host, port)
            send_notification_result(self.listener_descriptor, notification.identifier)
            return
        except PolicyViolation:
            error_number = errno.EACCES
        except OSError as error:
            error_number = error.errno or errno.EIO
        if not notification_valid(self.listener_descriptor, notification.identifier):
            return
        # Recording errors deliberately escape: the caller terminates the child
        # while its syscall is still blocked, rather than silently replying.
        record = emit_denial_record(
            self.identity, operation, target or "empty_path", error_number, self.output
        )
        self.denials.append(record)
        send_notification_result(
            self.listener_descriptor, notification.identifier, error_number=error_number
        )


def _execute(
    capability: CapabilityRecord,
    arguments: Mapping[str, str],
    identity: ExecutionIdentity,
    output: TextIO,
    *,
    procedure: str,
) -> ExecutionResult:
    load_kernel_support()
    workspace_descriptor = os.open(capability.workspace, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    parent_control, child_control = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    parent_control.settimeout(5)
    process: subprocess.Popen[bytes] | None = None
    listener_descriptor = -1
    process_descriptor = -1
    received_descriptors: list[int] = []
    deadline = time.monotonic() + MAXIMUM_EXECUTION_SECONDS
    try:
        # B603/S603: the module and interpreter are fixed; only one designated
        # bootstrap descriptor survives the fresh, isolated exec.
        process = subprocess.Popen(  # noqa: S603 # nosec B603
            [
                sys.executable,
                "-I",
                "-m",
                "confined_tool_execution.child",
                str(child_control.fileno()),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(child_control.fileno(),),
            cwd=capability.workspace,
            env=build_child_environment(),
        )
        child_control.close()
        request = {
            "capability": {**asdict(capability), "workspace": str(capability.workspace)},
            "arguments": dict(arguments),
            "procedure": procedure,
        }
        payload = json.dumps(request).encode()
        if len(payload) > 131072:
            raise PolicyViolation("execution_document_exceeds_bound")
        parent_control.sendall(payload)
        serialized, ancillary, message_flags, _ = parent_control.recvmsg(
            8192, socket.CMSG_SPACE(array.array("i").itemsize)
        )
        descriptors = array.array("i")
        for level, kind, data in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors.frombytes(data[: len(data) - len(data) % descriptors.itemsize])
        received_descriptors.extend(descriptors)
        if message_flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
            raise RuntimeError("truncated_bootstrap_response")
        if not serialized:
            raise RuntimeError("child_exited_before_confinement_readiness")
        readiness = json.loads(serialized)
        if readiness.get("state") == "unavailable":
            raise ConfinementUnavailable(str(readiness.get("error", "confinement_unavailable")))
        if readiness.get("state") != "ready" or len(descriptors) != 1:
            raise RuntimeError(f"invalid_confinement_readiness: {readiness}")
        listener_descriptor = descriptors[0]
        try:
            process_descriptor = os.pidfd_open(process.pid)
            verification_descriptor = duplicate_process_descriptor(
                process_descriptor, readiness["verification_descriptor"]
            )
            os.close(verification_descriptor)
            if (
                copy_process_bytes(process.pid, readiness["verification_address"], 11)
                != b"confinement"
            ):
                raise RuntimeError("process_memory_verification_failed")
        except OSError as error:
            if error.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS}:
                raise ConfinementUnavailable(
                    f"parent_process_inspection_unavailable: errno={error.errno}"
                ) from error
            raise
        supervisor = _NotificationSupervisor(
            capability,
            identity,
            workspace_descriptor,
            process_descriptor,
            process.pid,
            listener_descriptor,
            output,
        )
        parent_control.sendall(b"execute")
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("required_child_output_pipes_missing")
        report_bytes = bytearray()
        error_bytes = bytearray()
        with selectors.DefaultSelector() as events:
            events.register(listener_descriptor, selectors.EVENT_READ, "notification")
            events.register(process.stdout, selectors.EVENT_READ, "report")
            events.register(process.stderr, selectors.EVENT_READ, "error")
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError("confined_execution_deadline_exceeded")
                for event, _ in events.select(timeout=0.05):
                    if event.data == "notification":
                        try:
                            notification = get_notification(listener_descriptor)
                        except OSError as error:
                            if error.errno in {errno.EINTR, errno.ENOENT}:
                                continue
                            raise
                        supervisor.mediate(notification)
                    else:
                        block = os.read(event.fd, 8192)
                        if not block:
                            events.unregister(event.fileobj)
                            continue
                        destination = report_bytes if event.data == "report" else error_bytes
                        destination.extend(block)
                        if len(destination) > MAXIMUM_REPORT_BYTES:
                            raise RuntimeError("child_output_exceeds_bound")
        report_bytes.extend(process.stdout.read(MAXIMUM_REPORT_BYTES + 1))
        error_bytes.extend(process.stderr.read(MAXIMUM_REPORT_BYTES + 1))
        if len(report_bytes) > MAXIMUM_REPORT_BYTES or len(error_bytes) > MAXIMUM_REPORT_BYTES:
            raise RuntimeError("child_output_exceeds_bound")
        if process.returncode != 0:
            raise RuntimeError(
                f"confined_child_failed: {bytes(report_bytes)!r} {bytes(error_bytes)!r}"
            )
        response = json.loads(report_bytes)
        if response.get("state") != "complete" or not isinstance(response.get("report"), dict):
            raise RuntimeError("invalid_child_completion_record")
        return ExecutionResult(response["report"], tuple(supervisor.denials), readiness["support"])
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        parent_control.close()
        child_control.close()
        for descriptor in (process_descriptor, workspace_descriptor, *received_descriptors):
            if descriptor >= 0:
                os.close(descriptor)


def execute_confined(
    capability: CapabilityRecord,
    arguments: Mapping[str, str],
    identity: ExecutionIdentity,
    *,
    denial_output: TextIO | None = None,
) -> ExecutionResult:
    """Validate authority and execute only after mandatory kernel restrictions."""
    validate_capability(capability, arguments)
    validate_handler_arguments(arguments)
    validate_identity(identity)
    return _execute(
        capability,
        arguments,
        identity,
        sys.stdout if denial_output is None else denial_output,
        procedure="execution",
    )


def probe_confinement() -> dict[str, Any]:
    """Probe the complete parent/child mechanism, never weakening restrictions."""
    load_kernel_support()
    with tempfile.TemporaryDirectory(prefix="confinement-verification-") as directory:
        workspace = Path(directory).resolve()
        capability = CapabilityRecord(
            "127.0.0.1", 1, workspace, "workspace.reference", calculate_argument_digest({})
        )
        result = _execute(
            capability,
            {},
            ExecutionIdentity("verification_principal", "verification_capability"),
            io.StringIO(),
            procedure="probe",
        )
    if result.report != {"notification_roundtrip": True} or len(result.denials) != 1:
        raise RuntimeError("incomplete_confinement_probe")
    return {**result.mechanisms, "notification_roundtrip": True}
