"""Local authority records and fail-closed Linux process execution."""

from confined_tool_execution.linux import (
    ConfinementUnavailable,
    confine_process,
    restrict_egress,
    restrict_workspace,
)
from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity, ExecutionResult
from confined_tool_execution.records import emit_denial_record
from confined_tool_execution.supervisor import execute_confined, probe_confinement

__all__ = [
    "CapabilityRecord",
    "ConfinementUnavailable",
    "ExecutionIdentity",
    "ExecutionResult",
    "confine_process",
    "emit_denial_record",
    "execute_confined",
    "probe_confinement",
    "restrict_egress",
    "restrict_workspace",
]
