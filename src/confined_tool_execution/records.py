"""Supervisor-owned JSON-line evidence for denied operations."""

import json
from datetime import UTC, datetime
from typing import TextIO

from confined_tool_execution.models import DenialRecord, ExecutionIdentity
from confined_tool_execution.policy import PolicyViolation, validate_identity


def emit_denial_record(
    identity: ExecutionIdentity,
    operation: str,
    target: str,
    error_number: int | None,
    output: TextIO,
) -> DenialRecord:
    """Write and flush one denial record; output failure terminates the caller.

    The supervisor supplies observed operations and destinations. The child
    does not choose the identity, result, or timestamp of this evidence.
    """
    validate_identity(identity)
    if operation not in {"open", "connect", "exec"}:
        raise PolicyViolation("denial operation must be open, connect, or exec")
    if type(target) is not str or not 1 <= len(target) <= 4096:
        raise PolicyViolation("denial target must be a nonempty string of at most 4096 characters")
    if error_number is not None and (type(error_number) is not int or error_number <= 0):
        raise PolicyViolation("denial errno must be a positive integer or None")
    record = DenialRecord(
        timestamp=datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        principal_id=identity.principal_id,
        capability_id=identity.capability_id,
        operation=operation,
        target=target,
        result="denied",
        errno=error_number,
    )
    serialized = json.dumps(record.to_dict(), ensure_ascii=True, separators=(",", ":")) + "\n"
    if output.write(serialized) != len(serialized):
        raise OSError("denial record output was incomplete")
    output.flush()
    return record
