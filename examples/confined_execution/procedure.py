"""Phase B: verify workspace and audience restrictions with recorded denials."""

from __future__ import annotations

import json
import sys

from confined_tool_execution.linux import ConfinementUnavailable
from confined_tool_execution.supervisor import execute_confined
from fixtures.execution import ExecutionFixture


def main() -> None:
    with ExecutionFixture() as fixture:
        arguments = {**fixture.arguments, "metadata_probe": "yes", "execution_probe": "yes"}
        try:
            result = execute_confined(
                fixture.capability(arguments), arguments, fixture.identity, denial_output=sys.stderr
            )
        except ConfinementUnavailable as error:
            print(
                json.dumps(
                    {"phase": "confined_execution", "result": "unavailable", "reason": str(error)}
                ),
                file=sys.stderr,
            )
            raise SystemExit(2) from error
        report = result.report
        allowed = ("workspace_write", "workspace_read", "audience_connect")
        denied = ("outside_open", "other_connect", "metadata_connect", "execution")
        if not all(report[name]["allowed"] for name in allowed):
            raise RuntimeError("the confined handler did not complete its permitted operations")
        if any(report[name]["allowed"] for name in denied):
            raise RuntimeError("an operation outside the capability was permitted")
        if report["environment"] != ["LC_ALL"]:
            raise RuntimeError("the child environment exceeds the explicit allowlist")
        if not fixture.audience_listener.wait_for_connections(1):
            raise RuntimeError("the permitted audience connection was not observed")
        if fixture.other_listener.connection_count != 0:
            raise RuntimeError("the non-audience resource observed an unexpected connection")
        operations = {record.operation for record in result.denials}
        if not {"open", "connect", "exec"}.issubset(operations):
            raise RuntimeError("expected supervisor denial evidence is missing")
        print(
            json.dumps(
                {
                    "phase": "confined_execution",
                    "confinement": True,
                    "report": report,
                    "mechanisms": result.mechanisms,
                    "denials": [record.to_dict() for record in result.denials],
                    "audience_connections": fixture.audience_listener.connection_count,
                    "other_connections": fixture.other_listener.connection_count,
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
