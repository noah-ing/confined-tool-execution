"""Classify unavailable mechanisms without concealing implementation failures."""

import ctypes
import errno
import os
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from confined_tool_execution import linux

UNAVAILABLE_ERRORS = (errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES)
UNEXPECTED_ERRORS = (errno.EINVAL, errno.EFAULT, errno.EBADF)


@pytest.mark.parametrize("error_number", UNAVAILABLE_ERRORS)
def test_landlock_query_reports_known_unavailable_mechanism(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    query = Mock(return_value=-1)
    monkeypatch.setattr(linux, "_system_library", Mock(return_value=SimpleNamespace(syscall=query)))
    monkeypatch.setattr(ctypes, "get_errno", Mock(return_value=error_number))

    with pytest.raises(linux.ConfinementUnavailable, match="Landlock ABI query") as failure:
        linux._landlock_abi()

    assert isinstance(failure.value.__cause__, OSError)
    assert failure.value.__cause__.errno == error_number
    assert query.call_count == 1


@pytest.mark.parametrize("error_number", UNEXPECTED_ERRORS)
def test_landlock_query_keeps_unexpected_errors_visible(
    monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    query = Mock(return_value=-1)
    monkeypatch.setattr(linux, "_system_library", Mock(return_value=SimpleNamespace(syscall=query)))
    monkeypatch.setattr(ctypes, "get_errno", Mock(return_value=error_number))

    with pytest.raises(OSError) as failure:
        linux._landlock_abi()

    assert failure.value.errno == error_number
    assert query.call_count == 1


@pytest.mark.parametrize("mechanism", ["Landlock", "seccomp"])
@pytest.mark.parametrize("error_number", (*UNAVAILABLE_ERRORS, *UNEXPECTED_ERRORS))
def test_installation_failure_never_retries_or_weakens_confinement(
    monkeypatch: pytest.MonkeyPatch, mechanism: str, error_number: int
) -> None:
    support = linux.KernelSupport(3, "2.6.1")
    failure = OSError(error_number, "reference mechanism failure")
    workspace_installation = Mock(return_value=3)
    egress_installation = Mock(return_value=904)
    if mechanism == "Landlock":
        workspace_installation.side_effect = failure
    else:
        egress_installation.side_effect = failure
    monkeypatch.setattr(linux, "load_kernel_support", Mock(return_value=support))
    monkeypatch.setattr(os, "listdir", Mock(return_value=["501"]))
    monkeypatch.setattr(linux, "restrict_workspace", workspace_installation)
    monkeypatch.setattr(linux, "restrict_egress", egress_installation)

    if error_number in UNAVAILABLE_ERRORS:
        with pytest.raises(linux.ConfinementUnavailable, match=mechanism) as unavailable:
            linux.confine_process(901, 902)
        assert unavailable.value.__cause__ is failure
    else:
        with pytest.raises(OSError) as unexpected:
            linux.confine_process(901, 902)
        assert unexpected.value is failure

    workspace_installation.assert_called_once_with(901)
    if mechanism == "Landlock":
        egress_installation.assert_not_called()
    else:
        egress_installation.assert_called_once_with(902)
