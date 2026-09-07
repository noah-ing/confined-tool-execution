"""Local records for capability-scoped execution and supervisor evidence."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CapabilityRecord:
    """Authority already accepted by the calling resource.

    This local record does not verify a signature, attest a principal, or redeem
    a capability. Those decisions belong to the integrating resource.
    """

    audience_host: str
    audience_port: int
    workspace: Path
    tool_name: str
    argument_digest: str


@dataclass(frozen=True)
class ExecutionIdentity:
    """Resource-supplied identifiers attached to supervisor denial records."""

    principal_id: str
    capability_id: str


@dataclass(frozen=True)
class DenialRecord:
    """One denied operation observed and recorded by the supervisor."""

    timestamp: str
    principal_id: str
    capability_id: str
    operation: str
    target: str
    result: str
    errno: int | None

    def to_dict(self) -> dict[str, Any]:
        """Return a separate JSON-serializable representation."""
        return asdict(self)


@dataclass(frozen=True)
class ExecutionResult:
    """Handler report with independently collected supervisor evidence."""

    report: dict[str, Any]
    denials: tuple[DenialRecord, ...]
    mechanisms: dict[str, Any]
