"""Platform reporting and disposable reference resources."""

from __future__ import annotations

import os
import platform
from collections.abc import Iterator
from typing import Any

import pytest

from confined_tool_execution.models import ExecutionResult
from fixtures.execution import ExecutionFixture


@pytest.fixture(scope="session")
def linux_confinement() -> dict[str, Any]:
    required = os.environ.get("CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL") == "1"
    if platform.system() != "Linux":
        if required:
            pytest.fail("required Linux confinement cannot run on this platform")
        pytest.skip("linux_confinement requires Linux; portable policy tests remain enabled")
    from confined_tool_execution.linux import ConfinementUnavailable
    from confined_tool_execution.supervisor import probe_confinement

    try:
        return probe_confinement()
    except ConfinementUnavailable as error:
        if required:
            pytest.fail(f"required Linux confinement is unavailable: {error}")
        pytest.skip(f"linux_confinement is unavailable: {error}")


@pytest.fixture
def execution_fixture() -> Iterator[ExecutionFixture]:
    with ExecutionFixture() as fixture:
        yield fixture


@pytest.fixture
def confined_result(
    linux_confinement: dict[str, Any], execution_fixture: ExecutionFixture
) -> ExecutionResult:
    from confined_tool_execution.supervisor import execute_confined

    return execute_confined(
        execution_fixture.capability(), execution_fixture.arguments, execution_fixture.identity
    )
