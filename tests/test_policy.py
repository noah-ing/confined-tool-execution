"""Portable decisions and denial evidence; no Linux enforcement is assumed."""

import errno
import hashlib
import io
import json
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity
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


@pytest.fixture
def arguments() -> dict[str, str]:
    return {"output_name": "record.txt", "content": "reference contents"}


@pytest.fixture
def capability(tmp_path: Path, arguments: dict[str, str]) -> CapabilityRecord:
    return CapabilityRecord(
        audience_host="127.0.0.1",
        audience_port=12345,
        workspace=tmp_path.resolve(),
        tool_name="workspace.reference",
        argument_digest=calculate_argument_digest(arguments),
    )


def test_argument_digest_uses_documented_encoding() -> None:
    assert (
        calculate_argument_digest({"z": "café", "a": "value"})
        == hashlib.sha256('{"a":"value","z":"café"}'.encode()).hexdigest()
    )
    assert calculate_argument_digest({"a": "value", "z": "café"}) == calculate_argument_digest(
        {"z": "café", "a": "value"}
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"content": 1},
        {1: "content"},
        {"": "content"},
        {"n" * 129: "content"},
        {"content": "v" * 4097},
        {str(index): "value" for index in range(65)},
        {str(index): "v" * 4096 for index in range(16)},
        {"content": "\ud800"},
        ["content"],
    ],
)
def test_invalid_argument_representation_rejected(arguments: Any) -> None:
    with pytest.raises(PolicyViolation):
        calculate_argument_digest(arguments)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.2", "192.0.2.10"])
@pytest.mark.parametrize("port", [1, 65535])
def test_canonical_unicast_audience_accepted(host: str, port: int) -> None:
    validate_audience(host, port)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.1",
        "127.000.0.1",
        "127.0.0.1 ",
        "::1",
        "169.254.169.254",
        "169.254.1.1",
        "0.0.0.0",  # noqa: S104 - rejected policy input; no listener is created.
        "224.0.0.1",
        "255.255.255.255",
        "",
    ],
)
def test_invalid_or_metadata_audience_rejected(host: str) -> None:
    with pytest.raises(PolicyViolation):
        validate_audience(host, 12345)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "12345", 12345.0])
def test_invalid_audience_port_rejected(port: Any) -> None:
    with pytest.raises(PolicyViolation):
        validate_audience("127.0.0.1", port)


def test_matching_capability_accepted(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> None:
    validate_capability(capability, arguments)


def test_argument_substitution_rejected(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> None:
    with pytest.raises(PolicyViolation, match="do not match"):
        validate_capability(capability, {**arguments, "content": "substituted contents"})


@pytest.mark.parametrize(
    "changes",
    [
        {"tool_name": "other.reference"},
        {"argument_digest": "a" * 63},
        {"argument_digest": "A" * 64},
        {"workspace": Path("relative")},
        {"workspace": Path("/")},
        {"workspace": "not a Path"},
    ],
)
def test_invalid_capability_rejected(
    capability: CapabilityRecord, arguments: dict[str, str], changes: dict[str, Any]
) -> None:
    with pytest.raises(PolicyViolation):
        validate_capability(replace(capability, **changes), arguments)


def test_workspace_must_exist_as_directory(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> None:
    absent = capability.workspace / "absent"
    with pytest.raises(PolicyViolation):
        validate_capability(replace(capability, workspace=absent), arguments)
    regular_file = capability.workspace / "regular.txt"
    regular_file.write_text("reference")
    with pytest.raises(PolicyViolation):
        validate_capability(replace(capability, workspace=regular_file), arguments)


def test_workspace_symbolic_link_component_rejected(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> None:
    directory = capability.workspace / "directory"
    directory.mkdir()
    nested = directory / "nested"
    nested.mkdir()
    symbolic_link = capability.workspace / "reference_link"
    symbolic_link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(PolicyViolation, match="symbolic-link"):
        validate_capability(replace(capability, workspace=symbolic_link), arguments)
    with pytest.raises(PolicyViolation, match="symbolic-link"):
        validate_capability(replace(capability, workspace=symbolic_link / "nested"), arguments)


def test_workspace_parent_traversal_rejected(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> None:
    path = capability.workspace / ".." / capability.workspace.name
    with pytest.raises(PolicyViolation, match="parent traversal"):
        validate_capability(replace(capability, workspace=path), arguments)


def test_capability_record_is_immutable(capability: CapabilityRecord) -> None:
    with pytest.raises(FrozenInstanceError):
        capability.audience_port = 54321  # type: ignore[misc]


def test_workspace_relative_and_absolute_paths_are_equivalent(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    assert workspace_relative_path(workspace, "directory/record.txt") == "directory/record.txt"
    assert (
        workspace_relative_path(workspace, str(workspace / "directory" / "record.txt"))
        == "directory/record.txt"
    )
    assert workspace_relative_path(workspace, str(workspace)) == "."


@pytest.mark.parametrize("path", ["../outside", "directory/../../outside", "", "file\x00name"])
def test_workspace_invalid_relative_path_rejected(tmp_path: Path, path: str) -> None:
    with pytest.raises(PolicyViolation):
        workspace_relative_path(tmp_path.resolve(), path)


def test_workspace_sibling_prefix_is_outside(tmp_path: Path) -> None:
    workspace = tmp_path.resolve()
    with pytest.raises(PolicyViolation, match="outside"):
        workspace_relative_path(workspace, str(workspace) + "_sibling/record.txt")


def test_workspace_relative_descriptor_must_be_current_directory(tmp_path: Path) -> None:
    with pytest.raises(PolicyViolation, match="current workspace"):
        workspace_relative_path(tmp_path.resolve(), "record.txt", directory_descriptor=7)
    assert (
        workspace_relative_path(
            tmp_path.resolve(), str(tmp_path.resolve() / "record.txt"), directory_descriptor=7
        )
        == "record.txt"
    )


def test_workspace_path_byte_length_is_bounded(tmp_path: Path) -> None:
    with pytest.raises(PolicyViolation, match="encoded path"):
        workspace_relative_path(tmp_path.resolve(), "é" * 2049)


def test_child_environment_does_not_read_parent_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_names = (
        "AWS_ACCESS_KEY_ID",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "AUTHORIZATION",
        "HTTP_PROXY",
        "PYTHONPATH",
        "HOME",
    )
    for name in credential_names:
        monkeypatch.setenv(name, "generated-reference-value")
    environment = build_child_environment()
    assert environment == {"LC_ALL": "C.UTF-8"}
    environment["ADDED_BY_CALLER"] = "separate mapping"
    assert build_child_environment() == {"LC_ALL": "C.UTF-8"}


@pytest.mark.parametrize("identifier", ["", "with space", "with\nnewline", "a" * 129, "é"])
def test_invalid_execution_identifier_rejected(identifier: str) -> None:
    with pytest.raises(PolicyViolation):
        validate_identity(ExecutionIdentity(identifier, "capability.reference"))
    with pytest.raises(PolicyViolation):
        validate_identity(ExecutionIdentity("principal.reference", identifier))


def test_execution_identifiers_accept_reference_vocabulary() -> None:
    validate_identity(ExecutionIdentity("principal.reference-1", "capability:reference_2"))


@pytest.mark.parametrize("operation", ["open", "connect", "exec"])
def test_denial_record_schema_and_json_line(operation: str) -> None:
    output = io.StringIO()
    identity = ExecutionIdentity("principal.reference", "capability.reference")
    target = 'generated\nfilename".txt'
    record = emit_denial_record(identity, operation, target, errno.EACCES, output)
    assert len(output.getvalue().splitlines()) == 1
    document = json.loads(output.getvalue())
    assert document == record.to_dict()
    assert set(document) == {
        "timestamp",
        "principal_id",
        "capability_id",
        "operation",
        "target",
        "result",
        "errno",
    }
    assert document["principal_id"] == identity.principal_id
    assert document["capability_id"] == identity.capability_id
    assert document["operation"] == operation
    assert document["target"] == target
    assert document["result"] == "denied"
    assert document["errno"] == errno.EACCES
    timestamp = datetime.fromisoformat(document["timestamp"].replace("Z", "+00:00"))
    assert timestamp.utcoffset() == timedelta(0)
    assert document["timestamp"].endswith("Z")


def test_denial_record_unknown_errno_is_null() -> None:
    output = io.StringIO()
    emit_denial_record(ExecutionIdentity("principal", "capability"), "exec", "tool", None, output)
    assert json.loads(output.getvalue())["errno"] is None


@pytest.mark.parametrize(
    ("operation", "target", "error_number"),
    [("read", "file", 13), ("open", "", 13), ("open", "x" * 4097, 13), ("open", "file", True)],
)
def test_invalid_denial_record_rejected(operation: str, target: str, error_number: Any) -> None:
    output = io.StringIO()
    with pytest.raises(PolicyViolation):
        emit_denial_record(
            ExecutionIdentity("principal", "capability"), operation, target, error_number, output
        )
    assert output.getvalue() == ""


class UnavailableOutput(io.StringIO):
    def write(self, content: str) -> int:
        raise OSError("reference output unavailable")


class IncompleteOutput(io.StringIO):
    def write(self, content: str) -> int:
        return super().write(content[:-1])


class UnflushedOutput(io.StringIO):
    def flush(self) -> None:
        raise OSError("reference output cannot flush")


@pytest.mark.parametrize("output_type", [UnavailableOutput, IncompleteOutput, UnflushedOutput])
def test_denial_output_failure_propagates(output_type: type[io.StringIO]) -> None:
    with pytest.raises(OSError):
        emit_denial_record(
            ExecutionIdentity("principal", "capability"),
            "open",
            "file",
            errno.EACCES,
            output_type(),
        )
