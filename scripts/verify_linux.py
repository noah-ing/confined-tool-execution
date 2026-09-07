"""Require kernel evidence before accepting the Linux verification suite."""

import json
import os
import subprocess  # nosec B404
import sys

from confined_tool_execution.supervisor import probe_confinement


def main() -> None:
    print(json.dumps({"enforcement_preflight": probe_confinement()}, sort_keys=True), flush=True)
    for arguments in (
        ["-m", "pytest", "-q", "-p", "no:cacheprovider"],
        ["-m", "examples.unrestricted_demonstration.procedure"],
        ["-m", "examples.confined_execution.procedure"],
    ):
        subprocess.run(  # noqa: S603 # nosec B603
            [sys.executable, *arguments],
            check=True,
            timeout=180,
            env={**os.environ, "CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL": "1"},
        )


if __name__ == "__main__":
    main()
