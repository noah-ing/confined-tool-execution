"""Portable capability decisions made before irreversible Linux confinement."""

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from confined_tool_execution.models import CapabilityRecord, ExecutionIdentity

MAXIMUM_ARGUMENT_COUNT = 64
MAXIMUM_ARGUMENT_KEY_LENGTH = 128
MAXIMUM_ARGUMENT_VALUE_LENGTH = 4096
MAXIMUM_ARGUMENT_BYTES = 65536
MAXIMUM_PATH_LENGTH = 4096
CURRENT_DIRECTORY_DESCRIPTOR = -100
SUPPORTED_TOOL_NAME = "workspace.reference"
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


class PolicyViolation(ValueError):
    """The supplied local authority or requested operation is not acceptable."""


def calculate_argument_digest(arguments: Mapping[str, str]) -> str:
    """Hash bounded string arguments using the reference's exact JSON encoding.

    Keys are sorted, Unicode characters are encoded directly as UTF-8, and JSON
    separators contain no optional whitespace. This is a local format rather
    than a claim of implementing a general JSON canonicalization standard.
    """
    if not isinstance(arguments, Mapping):
        raise PolicyViolation("arguments must be a mapping of strings to strings")
    if len(arguments) > MAXIMUM_ARGUMENT_COUNT:
        raise PolicyViolation("argument count exceeds the reference limit")
    document: dict[str, str] = {}
    for name, value in arguments.items():
        if type(name) is not str or type(value) is not str:
            raise PolicyViolation("argument names and values must be strings")
        if not 1 <= len(name) <= MAXIMUM_ARGUMENT_KEY_LENGTH:
            raise PolicyViolation("argument name length is outside the reference limit")
        if len(value) > MAXIMUM_ARGUMENT_VALUE_LENGTH:
            raise PolicyViolation("argument value length exceeds the reference limit")
        document[name] = value
    try:
        serialized = json.dumps(
            document, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except UnicodeEncodeError as error:
        raise PolicyViolation("argument strings must have a valid UTF-8 representation") from error
    if len(serialized) > MAXIMUM_ARGUMENT_BYTES:
        raise PolicyViolation("encoded arguments exceed the reference limit")
    return hashlib.sha256(serialized).hexdigest()


def validate_audience(host: str, port: int) -> None:
    """Accept one exact numeric IPv4 TCP endpoint, with no DNS resolution."""
    if type(host) is not str or len(host) > 15:
        raise PolicyViolation("audience host must be a canonical numeric IPv4 address")
    try:
        address = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError as error:
        raise PolicyViolation("audience host must be a canonical numeric IPv4 address") from error
    if str(address) != host:
        raise PolicyViolation("audience host must use canonical IPv4 notation")
    if (
        address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise PolicyViolation("audience address is outside the reference policy")
    if type(port) is not int or not 1 <= port <= 65535:
        raise PolicyViolation("audience port must be an integer from 1 to 65535")


def _validate_workspace(workspace: Path) -> None:
    if not isinstance(workspace, Path):
        raise PolicyViolation("workspace must be a Path")
    if not workspace.is_absolute() or workspace == Path(workspace.anchor):
        raise PolicyViolation("workspace must be an absolute directory other than filesystem root")
    _validate_path_text(str(workspace))
    if ".." in workspace.parts:
        raise PolicyViolation("workspace must not contain parent traversal")
    try:
        if any(component.is_symlink() for component in (workspace, *workspace.parents)):
            raise PolicyViolation("workspace must not contain symbolic-link components")
        if workspace.resolve(strict=True) != workspace or not workspace.is_dir():
            raise PolicyViolation("workspace must name an existing canonical directory")
    except (OSError, RuntimeError) as error:
        raise PolicyViolation("workspace cannot be resolved as an existing directory") from error


def validate_capability(capability: CapabilityRecord, arguments: Mapping[str, str]) -> None:
    """Reject unsupported or mismatched authority before a tool can run."""
    if not isinstance(capability, CapabilityRecord):
        raise PolicyViolation("capability must be a CapabilityRecord")
    validate_audience(capability.audience_host, capability.audience_port)
    _validate_workspace(capability.workspace)
    if capability.tool_name != SUPPORTED_TOOL_NAME:
        raise PolicyViolation("capability names an unsupported tool")
    if type(capability.argument_digest) is not str or not DIGEST_PATTERN.fullmatch(
        capability.argument_digest
    ):
        raise PolicyViolation("argument digest must be a lowercase SHA-256 hexadecimal value")
    if calculate_argument_digest(arguments) != capability.argument_digest:
        raise PolicyViolation("requested arguments do not match the capability digest")


def _validate_path_text(path: str) -> None:
    if type(path) is not str or not 1 <= len(path) <= MAXIMUM_PATH_LENGTH:
        raise PolicyViolation("path must be a nonempty bounded string")
    if "\x00" in path:
        raise PolicyViolation("path must not contain a null character")
    try:
        encoded_path = path.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PolicyViolation("path must have a valid UTF-8 representation") from error
    if len(encoded_path) > MAXIMUM_PATH_LENGTH:
        raise PolicyViolation("encoded path exceeds the reference limit")


def workspace_relative_path(
    workspace: Path, path: str, directory_descriptor: int = CURRENT_DIRECTORY_DESCRIPTOR
) -> str:
    """Check lexical containment and return a path relative to the workspace.

    This decision is not a filesystem-open authorization by itself. The
    supervisor must resolve the returned path with race-resistant ``openat2``
    restrictions beneath its previously opened workspace descriptor.
    """
    _validate_path_text(path)
    if not isinstance(workspace, Path) or not workspace.is_absolute():
        raise PolicyViolation("workspace must be an absolute Path")
    workspace_path = PurePosixPath(workspace.as_posix())
    if workspace == Path(workspace.anchor) or ".." in workspace_path.parts:
        raise PolicyViolation("workspace must be a non-root path without parent traversal")
    native_path = Path(path)
    requested_path = PurePosixPath(native_path.as_posix())
    if ".." in requested_path.parts:
        raise PolicyViolation("requested path must not contain parent traversal")
    if native_path.is_absolute():
        try:
            relative_path = requested_path.relative_to(workspace_path)
        except ValueError as error:
            raise PolicyViolation("requested path is outside the workspace") from error
    else:
        if directory_descriptor != CURRENT_DIRECTORY_DESCRIPTOR:
            raise PolicyViolation("relative requests must use the current workspace directory")
        relative_path = requested_path
    return str(relative_path)


def build_child_environment() -> dict[str, str]:
    """Construct the entire child environment without reading the parent's."""
    return {"LC_ALL": "C.UTF-8"}


def validate_identity(identity: ExecutionIdentity) -> None:
    """Accept bounded identifiers suitable for supervisor-owned evidence."""
    if not isinstance(identity, ExecutionIdentity):
        raise PolicyViolation("identity must be an ExecutionIdentity")
    for identifier in (identity.principal_id, identity.capability_id):
        if type(identifier) is not str or not IDENTIFIER_PATTERN.fullmatch(identifier):
            raise PolicyViolation("execution identifiers must use 1 to 128 safe ASCII characters")
