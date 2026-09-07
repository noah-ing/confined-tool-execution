"""Phase A: execute the reference handler in a separate unrestricted process."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any

from confined_tool_execution.handler import execute_reference_handler
from confined_tool_execution.models import CapabilityRecord
from confined_tool_execution.policy import (
    build_child_environment,
    calculate_argument_digest,
    validate_capability,
)
from fixtures.execution import OUTSIDE_CONTENT, ExecutionFixture

_EXECUTION_SOURCE = (
    "import runpy, sys; "
    "sys.path[:0] = sys.argv[1:3]; "
    "sys.argv = ['execution_procedure', '--execution-fixture']; "
    "runpy.run_module('examples.unrestricted_demonstration.procedure', run_name='__main__')"
)


def _validate_fixture(capability: CapabilityRecord, arguments: dict[str, str]) -> None:
    validate_capability(capability, arguments)
    if not ipaddress.IPv4Address(capability.audience_host).is_loopback:
        raise ValueError("unrestricted fixtures require a loopback audience")
    other_address = ipaddress.IPv4Address(arguments["other_host"])
    if not other_address.is_loopback or str(other_address) != arguments["other_host"]:
        raise ValueError("unrestricted fixtures require a second loopback resource")
    if arguments.get("metadata_probe", "no") != "no":
        raise ValueError("unrestricted fixtures never probe metadata endpoints")
    if arguments.get("execution_probe", "no") != "no":
        raise ValueError("unrestricted fixtures never execute another program")
    outside_path = Path(arguments["outside_path"])
    expected_outside = capability.workspace.parent / "outside_record.txt"
    if (
        capability.workspace.name != "workspace"
        or outside_path != expected_outside
        or outside_path.resolve(strict=True) != expected_outside
        or outside_path.read_text(encoding="utf-8") != OUTSIDE_CONTENT
    ):
        raise ValueError("unrestricted fixtures require the generated sibling file")
    if arguments.get("output_name", "record.txt") != "record.txt":
        raise ValueError("unrestricted fixtures write only the generated workspace record")


def run_unrestricted_fixture(
    capability: CapabilityRecord, arguments: dict[str, str]
) -> dict[str, Any]:
    """Run the exact library handler without invoking the confinement library.

    This example-only subprocess always uses disposable file paths and loopback
    addresses. There is no library parameter that disables enforcement.
    """
    _validate_fixture(capability, arguments)
    repository = Path(__file__).resolve().parents[2]
    document = {
        "workspace": str(capability.workspace),
        "audience_host": capability.audience_host,
        "audience_port": capability.audience_port,
        "arguments": arguments,
    }
    # B404/B603/S603: a fixed interpreter receives fixed source roots and no shell.
    result = subprocess.run(  # noqa: S603 # nosec B603
        [sys.executable, "-I", "-c", _EXECUTION_SOURCE, str(repository), str(repository / "src")],
        input=json.dumps(document),
        text=True,
        capture_output=True,
        close_fds=True,
        timeout=10,
        check=True,
        env=build_child_environment(),
    )
    report: Any = json.loads(result.stdout)
    if not isinstance(report, dict) or not all(isinstance(name, str) for name in report):
        raise ValueError("unrestricted fixture returned an invalid report")
    return report


def _execute_fixture_document() -> None:
    serialized = sys.stdin.read(65537)
    if len(serialized) > 65536:
        raise ValueError("fixture document exceeds its size bound")
    document: Any = json.loads(serialized)
    if not isinstance(document, dict) or set(document) != {
        "workspace",
        "audience_host",
        "audience_port",
        "arguments",
    }:
        raise ValueError("fixture document has unsupported fields")
    arguments = document["arguments"]
    if not isinstance(arguments, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in arguments.items()
    ):
        raise ValueError("fixture arguments must be strings")
    if not isinstance(document["workspace"], str):
        raise ValueError("fixture workspace must be a string")
    capability = CapabilityRecord(
        audience_host=document["audience_host"],
        audience_port=document["audience_port"],
        workspace=Path(document["workspace"]),
        tool_name="workspace.reference",
        argument_digest=calculate_argument_digest(arguments),
    )
    _validate_fixture(capability, arguments)
    # Some host runtimes add environment entries during interpreter startup.
    # Remove those additions after fixture setup, immediately before the same
    # handler runs. This example cleanup does not establish Linux confinement.
    os.environ.clear()
    os.environ.update(build_child_environment())
    print(json.dumps(execute_reference_handler(capability, arguments), sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-fixture", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.execution_fixture:
        _execute_fixture_document()
        return
    with ExecutionFixture() as fixture:
        report = run_unrestricted_fixture(fixture.capability(), fixture.arguments)
        required = (
            "workspace_write",
            "workspace_read",
            "outside_open",
            "audience_connect",
            "other_connect",
        )
        if not all(report[name]["allowed"] for name in required):
            raise RuntimeError(
                "the unrestricted fixture did not establish its expected observations"
            )
        if not fixture.audience_listener.wait_for_connections(1):
            raise RuntimeError("the audience fixture did not observe the connection")
        if not fixture.other_listener.wait_for_connections(1):
            raise RuntimeError("the non-audience fixture did not observe the connection")
        print(
            json.dumps(
                {
                    "phase": "unrestricted_demonstration",
                    "confinement": False,
                    "report": report,
                    "audience_connections": fixture.audience_listener.connection_count,
                    "other_connections": fixture.other_listener.connection_count,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
