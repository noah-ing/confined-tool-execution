"""Actual process outcomes and independently observed denial evidence."""

from __future__ import annotations

import errno
import inspect
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity, ExecutionResult
from confined_tool_execution.policy import PolicyViolation, calculate_argument_digest
from examples.unrestricted_demonstration.procedure import run_unrestricted_fixture
from fixtures.execution import OUTSIDE_CONTENT, ExecutionFixture


def _denied(outcome: dict[str, Any]) -> None:
    assert outcome["allowed"] is False
    assert isinstance(outcome["errno"], int)
    assert outcome["errno"] != 0
    assert "content" not in outcome


def _portable_request(
    workspace: Path,
) -> tuple[CapabilityRecord, dict[str, str], ExecutionIdentity]:
    arguments = {
        "outside_path": str(workspace.parent / "outside_record.txt"),
        "other_host": "127.0.0.1",
        "other_port": "12346",
    }
    capability = CapabilityRecord(
        "127.0.0.1", 12345, workspace, "workspace.reference", calculate_argument_digest(arguments)
    )
    return capability, arguments, ExecutionIdentity("principal.reference", "capability.reference")


def test_missing_mechanism_prevents_process_and_handler_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from confined_tool_execution import handler, supervisor
    from confined_tool_execution.linux import ConfinementUnavailable

    capability, arguments, identity = _portable_request(tmp_path.resolve())
    unavailable = Mock(side_effect=ConfinementUnavailable("generated unavailable mechanism"))
    launcher = Mock(
        side_effect=AssertionError("an unavailable mechanism must prevent process launch")
    )
    invocation = Mock(
        side_effect=AssertionError("an unavailable mechanism must prevent handler use")
    )
    monkeypatch.setattr(supervisor, "load_kernel_support", unavailable)
    monkeypatch.setattr("confined_tool_execution.supervisor.subprocess.Popen", launcher)
    monkeypatch.setattr(handler, "execute_reference_handler", invocation)
    with pytest.raises(ConfinementUnavailable, match="generated unavailable mechanism"):
        supervisor.execute_confined(capability, arguments, identity)
    unavailable.assert_called_once_with()
    launcher.assert_not_called()
    invocation.assert_not_called()


def test_argument_digest_rejected_before_process_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from confined_tool_execution import handler, supervisor

    capability, arguments, identity = _portable_request(tmp_path.resolve())
    support = Mock(
        side_effect=AssertionError("invalid arguments must not reach kernel preparation")
    )
    launcher = Mock(side_effect=AssertionError("invalid arguments must not launch a child"))
    invocation = Mock(side_effect=AssertionError("invalid arguments must not invoke the handler"))
    monkeypatch.setattr(supervisor, "load_kernel_support", support)
    monkeypatch.setattr("confined_tool_execution.supervisor.subprocess.Popen", launcher)
    monkeypatch.setattr(handler, "execute_reference_handler", invocation)
    with pytest.raises(PolicyViolation, match="do not match"):
        supervisor.execute_confined(capability, {**arguments, "other_port": "12347"}, identity)
    support.assert_not_called()
    launcher.assert_not_called()
    invocation.assert_not_called()


@pytest.mark.linux_confinement
def test_workspace_open_outside_denied(
    confined_result: ExecutionResult, execution_fixture: ExecutionFixture
) -> None:
    _denied(confined_result.report["outside_open"])
    assert execution_fixture.outside_path.read_text() == OUTSIDE_CONTENT


@pytest.mark.linux_confinement
def test_system_file_open_denied(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    arguments = {**execution_fixture.arguments, "outside_path": "/etc/passwd"}
    result = execute_confined(
        execution_fixture.capability(arguments), arguments, execution_fixture.identity
    )
    _denied(result.report["outside_open"])
    assert any(
        record.operation == "open" and record.target == "/etc/passwd" for record in result.denials
    )


@pytest.mark.linux_confinement
def test_parent_home_record_open_denied(
    linux_confinement: dict[str, Any],
    execution_fixture: ExecutionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    home_directory = execution_fixture.workspace.parent / "principal_home"
    home_directory.mkdir(mode=0o700)
    home_record = home_directory / "credential_record.txt"
    home_record.write_text("generated reference credential\n")
    monkeypatch.setenv("HOME", str(home_directory))
    arguments = {**execution_fixture.arguments, "outside_path": str(home_record)}
    result = execute_confined(
        execution_fixture.capability(arguments), arguments, execution_fixture.identity
    )
    _denied(result.report["outside_open"])
    assert result.report["environment"] == ["LC_ALL"]
    assert home_record.read_text() == "generated reference credential\n"
    assert any(
        record.operation == "open" and record.target == str(home_record)
        for record in result.denials
    )


@pytest.mark.linux_confinement
def test_workspace_open_inside_allowed(
    confined_result: ExecutionResult, execution_fixture: ExecutionFixture
) -> None:
    assert confined_result.report["workspace_write"] == {"allowed": True, "errno": None}
    assert confined_result.report["workspace_read"]["allowed"] is True
    assert confined_result.report["workspace_read"]["content"] == "reference record\n"
    assert (execution_fixture.workspace / "record.txt").read_text() == "reference record\n"


@pytest.mark.linux_confinement
def test_egress_non_audience_denied(
    confined_result: ExecutionResult, execution_fixture: ExecutionFixture
) -> None:
    _denied(confined_result.report["other_connect"])
    assert execution_fixture.other_listener.connection_count == 0


@pytest.mark.linux_confinement
def test_egress_audience_allowed(
    confined_result: ExecutionResult, execution_fixture: ExecutionFixture
) -> None:
    assert confined_result.report["audience_connect"]["allowed"] is True
    assert confined_result.report["audience_connect"]["errno"] is None
    assert execution_fixture.audience_listener.wait_for_connections(1)
    assert execution_fixture.audience_listener.connection_count == 1


@pytest.mark.linux_confinement
def test_egress_other_host_on_audience_port_denied(linux_confinement: dict[str, Any]) -> None:
    from confined_tool_execution.supervisor import execute_confined

    with ExecutionFixture(other_host="127.0.0.2", same_audience_port=True) as fixture:
        result = execute_confined(fixture.capability(), fixture.arguments, fixture.identity)
        assert fixture.audience_listener.port == fixture.other_listener.port
        assert fixture.audience_listener.host != fixture.other_listener.host
        _denied(result.report["other_connect"])
        assert result.report["audience_connect"]["allowed"] is True
        assert fixture.audience_listener.wait_for_connections(1)
        assert fixture.other_listener.connection_count == 0


@pytest.mark.linux_confinement
def test_link_local_metadata_endpoint_denied(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    arguments = {**execution_fixture.arguments, "metadata_probe": "yes"}
    result = execute_confined(
        execution_fixture.capability(arguments), arguments, execution_fixture.identity
    )
    _denied(result.report["metadata_connect"])
    assert any(
        record.operation == "connect"
        and "169.254.169.254" in record.target
        and record.result == "denied"
        for record in result.denials
    )


@pytest.mark.linux_confinement
def test_ambient_credential_names_absent(
    linux_confinement: dict[str, Any],
    execution_fixture: ExecutionFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    names = (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN",
        "AUTHORIZATION",
        "HTTP_PROXY",
        "PYTHONPATH",
        "HOME",
    )
    for name in names:
        monkeypatch.setenv(name, "generated-reference-value")
    result = execute_confined(
        execution_fixture.capability(), execution_fixture.arguments, execution_fixture.identity
    )
    assert result.report["environment"] == ["LC_ALL"]
    assert not set(names).intersection(result.report["environment"])


@pytest.mark.linux_confinement
def test_denial_record_emitted_on_denied_open(
    confined_result: ExecutionResult, execution_fixture: ExecutionFixture
) -> None:
    _denied(confined_result.report["outside_open"])
    matching = [
        record
        for record in confined_result.denials
        if record.operation == "open" and record.target == str(execution_fixture.outside_path)
    ]
    assert len(matching) == 1
    record = matching[0]
    assert record.principal_id == execution_fixture.identity.principal_id
    assert record.capability_id == execution_fixture.identity.capability_id
    assert record.result == "denied"
    assert record.errno == confined_result.report["outside_open"]["errno"]
    assert record.timestamp.endswith("Z")


@pytest.mark.linux_confinement
def test_denial_record_emitted_on_denied_connect(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    output = io.StringIO()
    result = execute_confined(
        execution_fixture.capability(),
        execution_fixture.arguments,
        execution_fixture.identity,
        denial_output=output,
    )
    _denied(result.report["other_connect"])
    documents = [json.loads(line) for line in output.getvalue().splitlines()]
    assert documents == [record.to_dict() for record in result.denials]
    matches = [
        document
        for document in documents
        if document["operation"] == "connect"
        and document["target"]
        == f"{execution_fixture.other_listener.host}:{execution_fixture.other_listener.port}"
    ]
    assert len(matches) == 1
    assert matches[0]["result"] == "denied"
    assert matches[0]["errno"] == result.report["other_connect"]["errno"]
    assert matches[0]["principal_id"] == execution_fixture.identity.principal_id
    assert matches[0]["capability_id"] == execution_fixture.identity.capability_id
    assert execution_fixture.other_listener.connection_count == 0


def test_unrestricted_demonstration_succeeds_when_confinement_disabled(
    execution_fixture: ExecutionFixture,
) -> None:
    report = run_unrestricted_fixture(execution_fixture.capability(), execution_fixture.arguments)
    assert report["outside_open"]["allowed"] is True
    assert report["outside_open"]["content"] == OUTSIDE_CONTENT
    assert report["other_connect"]["allowed"] is True
    assert report["workspace_write"]["allowed"] is True
    assert report["workspace_read"]["content"] == "reference record\n"
    assert report["audience_connect"]["allowed"] is True
    assert report["environment"] == ["LC_ALL"]
    assert "metadata_connect" not in report
    assert "execution" not in report
    assert execution_fixture.other_listener.wait_for_connections(1)
    assert execution_fixture.audience_listener.wait_for_connections(1)


@pytest.mark.linux_confinement
def test_library_default_confinement_enabled(confined_result: ExecutionResult) -> None:
    from confined_tool_execution.supervisor import execute_confined

    parameters = inspect.signature(execute_confined).parameters
    assert "confinement" not in parameters
    assert "confinement_enabled" not in parameters
    assert "disabled" not in parameters
    _denied(confined_result.report["outside_open"])
    _denied(confined_result.report["other_connect"])
    assert confined_result.mechanisms


@pytest.mark.linux_confinement
def test_workspace_symbolic_link_open_denied(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    symbolic_link = execution_fixture.workspace / "record.txt"
    symbolic_link.symlink_to(execution_fixture.outside_path)
    result = execute_confined(
        execution_fixture.capability(), execution_fixture.arguments, execution_fixture.identity
    )
    _denied(result.report["workspace_write"])
    _denied(result.report["workspace_read"])
    assert execution_fixture.outside_path.read_text() == OUTSIDE_CONTENT
    assert any(
        record.operation == "open" and "record.txt" in record.target for record in result.denials
    )


@pytest.mark.linux_confinement
def test_new_execution_denied_with_record(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    arguments = {**execution_fixture.arguments, "execution_probe": "yes"}
    result = execute_confined(
        execution_fixture.capability(arguments), arguments, execution_fixture.identity
    )
    _denied(result.report["execution"])
    assert any(
        record.operation == "exec" and record.target == "/bin/true" for record in result.denials
    )


class UnavailableDenialOutput(io.StringIO):
    def write(self, content: str) -> int:
        raise OSError(errno.ENOSPC, "generated unavailable denial output")


@pytest.mark.linux_confinement
def test_denial_output_failure_terminates_execution(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> None:
    from confined_tool_execution.supervisor import execute_confined

    with pytest.raises(OSError, match="denial output"):
        execute_confined(
            execution_fixture.capability(),
            execution_fixture.arguments,
            execution_fixture.identity,
            denial_output=UnavailableDenialOutput(),
        )
    assert execution_fixture.audience_listener.connection_count == 0
    assert execution_fixture.other_listener.connection_count == 0
