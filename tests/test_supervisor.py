"""Portable mediation regressions with all kernel notification I/O replaced."""

import errno
import io
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from typing import TextIO
from unittest.mock import Mock

import pytest

from confined_tool_execution import supervisor
from confined_tool_execution.linux import Notification
from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity


def _notification(name: str, arguments: tuple[int, ...]) -> Notification:
    return Notification(41, 501, name, arguments + (0,) * (6 - len(arguments)))


def _notification_supervisor(workspace: Path, output: TextIO) -> supervisor._NotificationSupervisor:
    capability = CapabilityRecord("127.0.0.1", 12345, workspace, "workspace.reference", "0" * 64)
    return supervisor._NotificationSupervisor(
        capability,
        ExecutionIdentity("principal.reference", "capability.reference"),
        workspace_descriptor=901,
        process_descriptor=902,
        child_process_id=501,
        listener_descriptor=903,
        output=output,
    )


@pytest.fixture
def linux_open_constants(monkeypatch: pytest.MonkeyPatch) -> None:
    # Only integer flag interpretation is under test. Supplying the Linux UAPI
    # constants keeps these rejection tests independent of the host OS and
    # gives them no open/stat methods with which to perform filesystem I/O.
    monkeypatch.setattr(
        supervisor,
        "os",
        SimpleNamespace(
            O_ACCMODE=0o3,
            O_RDONLY=0,
            O_WRONLY=0o1,
            O_RDWR=0o2,
            O_CREAT=0o100,
            O_EXCL=0o200,
            O_TRUNC=0o1000,
            O_APPEND=0o2000,
            O_NONBLOCK=0o4000,
            O_DIRECTORY=0o200000,
            O_NOFOLLOW=0o400000,
            O_CLOEXEC=0o2000000,
            O_PATH=0o10000000,
        ),
    )


@pytest.mark.parametrize(
    ("flags", "mode", "reason"),
    [
        ((1 << 40) | 0o101, 0o600, "unsupported_open_flags"),
        (0o101, (1 << 40) | 0o600, "unsupported_creation_mode"),
    ],
)
def test_openat2_high_bits_rejected_before_filesystem_access(
    monkeypatch: pytest.MonkeyPatch,
    linux_open_constants: None,
    flags: int,
    mode: int,
    reason: str,
) -> None:
    notification = _notification("openat2", (0xFFFFFF9C, 0x1000, 0x2000, 24))
    monkeypatch.setattr(
        supervisor, "copy_process_bytes", Mock(return_value=struct.pack("=QQQ", flags, mode, 0))
    )
    monkeypatch.setattr(supervisor, "copy_process_string", Mock(return_value="record.txt"))
    filesystem_open = Mock(side_effect=AssertionError("invalid authority reached file opening"))
    monkeypatch.setattr(supervisor, "open_workspace_descriptor", filesystem_open)

    path, directory, decoded_flags, decoded_mode = supervisor._open_arguments(notification)

    assert (path, directory) == ("record.txt", -100)
    assert (decoded_flags, decoded_mode) == (flags, mode)
    with pytest.raises(OSError, match=reason) as failure:
        supervisor._open_permitted_file(901, path, decoded_flags, decoded_mode)
    assert failure.value.errno == errno.EACCES
    filesystem_open.assert_not_called()


@pytest.mark.parametrize(
    ("name", "directory"),
    [
        ("open", 0),
        ("openat", 0xFFFFFF9C),
        ("openat", 0xFFFFFFFFFFFFFF9C),
        ("openat", 0xABCDEF12FFFFFF9C),
    ],
)
def test_open_integer_arguments_follow_native_width(
    monkeypatch: pytest.MonkeyPatch, name: str, directory: int
) -> None:
    native_flags = 0o101
    native_mode = 0o600
    supplied_flags = (0xABCDEF12 << 32) | native_flags
    supplied_mode = (0x12345678 << 32) | native_mode
    arguments: tuple[int, ...] = (0x1000, supplied_flags, supplied_mode)
    if name == "openat":
        arguments = (directory, *arguments)
    copied_path = Mock(return_value="record.txt")
    monkeypatch.setattr(supervisor, "copy_process_string", copied_path)

    decoded = supervisor._open_arguments(_notification(name, arguments))

    assert decoded == ("record.txt", -100, native_flags, native_mode)
    copied_path.assert_called_once_with(501, 0x1000)


def test_openat_positive_directory_uses_native_descriptor_width(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supervisor, "copy_process_string", Mock(return_value="record.txt"))
    notification = _notification("openat", ((1 << 32) | 7, 0x1000, 0, 0))

    assert supervisor._open_arguments(notification) == ("record.txt", 7, 0, 0)


@pytest.mark.parametrize("path", ["", "record_\udcff.txt"])
def test_invalid_path_denial_remains_json_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, path: str
) -> None:
    output = io.StringIO()
    mediation = _notification_supervisor(tmp_path.resolve(), output)
    monkeypatch.setattr(supervisor, "notification_valid", Mock(return_value=True))
    monkeypatch.setattr(supervisor, "copy_process_string", Mock(return_value=path))
    filesystem_open = Mock(side_effect=AssertionError("invalid path reached file opening"))
    response = Mock()
    monkeypatch.setattr(supervisor, "_open_permitted_file", filesystem_open)
    monkeypatch.setattr(supervisor, "send_notification_result", response)

    mediation.mediate(_notification("open", (0x1000, 0, 0)))

    serialized = output.getvalue()
    # No unpaired surrogate may prevent writing the JSON-line artifact as UTF-8.
    serialized.encode("utf-8", errors="strict")
    assert len(serialized.splitlines()) == 1
    record = json.loads(serialized)
    assert record["target"] == (path or "empty_path")
    assert record["operation"] == "open"
    assert record["result"] == "denied"
    assert record["errno"] == errno.EACCES
    assert record["principal_id"] == "principal.reference"
    assert record["capability_id"] == "capability.reference"
    assert [denial.to_dict() for denial in mediation.denials] == [record]
    filesystem_open.assert_not_called()
    response.assert_called_once_with(903, 41, error_number=errno.EACCES)


class UnavailableDenialOutput(io.StringIO):
    def write(self, content: str) -> int:
        raise OSError("denial output unavailable")


class IncompleteDenialOutput(io.StringIO):
    def write(self, content: str) -> int:
        return super().write(content[:-1])


class UnflushedDenialOutput(io.StringIO):
    def flush(self) -> None:
        raise OSError("denial output cannot flush")


@pytest.mark.parametrize(
    "output_type", [UnavailableDenialOutput, IncompleteDenialOutput, UnflushedDenialOutput]
)
def test_denial_output_failure_prevents_notification_response(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, output_type: type[io.StringIO]
) -> None:
    mediation = _notification_supervisor(tmp_path.resolve(), output_type())
    monkeypatch.setattr(supervisor, "notification_valid", Mock(return_value=True))
    monkeypatch.setattr(supervisor, "copy_process_string", Mock(return_value="../outside.txt"))
    filesystem_open = Mock(side_effect=AssertionError("outside path reached file opening"))
    response = Mock()
    monkeypatch.setattr(supervisor, "_open_permitted_file", filesystem_open)
    monkeypatch.setattr(supervisor, "send_notification_result", response)

    with pytest.raises(OSError, match="output"):
        mediation.mediate(_notification("open", (0x1000, 0, 0)))

    assert mediation.denials == []
    filesystem_open.assert_not_called()
    response.assert_not_called()
