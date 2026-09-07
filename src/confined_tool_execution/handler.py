"""One fixed handler; all denied-operation evidence belongs to the supervisor."""

import ipaddress
import os
import socket
from collections.abc import Mapping
from typing import Any

from confined_tool_execution.models import CapabilityRecord
from confined_tool_execution.policy import PolicyViolation

REFERENCE_CONTENT = b"reference record\n"


def validate_handler_arguments(arguments: Mapping[str, str]) -> None:
    required = {"outside_path", "other_host", "other_port"}
    optional = {"output_name", "metadata_probe", "execution_probe"}
    if not required <= arguments.keys() or arguments.keys() - required - optional:
        raise PolicyViolation("unsupported_reference_arguments")
    if not os.path.isabs(arguments["outside_path"]) or "\x00" in arguments["outside_path"]:
        raise PolicyViolation("outside_fixture_path_must_be_absolute")
    try:
        address = ipaddress.IPv4Address(arguments["other_host"])
        port = int(arguments["other_port"])
    except ValueError as error:
        raise PolicyViolation("invalid_reference_endpoint") from error
    if str(address) != arguments["other_host"] or not 1 <= port <= 65535:
        raise PolicyViolation("invalid_reference_endpoint")
    name = arguments.get("output_name", "record.txt")
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise PolicyViolation("output_name_must_be_one_component")
    if any(arguments.get(key, "no") not in {"yes", "no"} for key in optional - {"output_name"}):
        raise PolicyViolation("invalid_reference_probe_selection")


def _read_record(path: str) -> dict[str, Any]:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            content = os.read(descriptor, 4096).decode("utf-8", errors="replace")
        finally:
            os.close(descriptor)
        return {"allowed": True, "errno": None, "content": content}
    except OSError as error:
        return {"allowed": False, "errno": error.errno}


def _connect_resource(host: str, port: int) -> dict[str, Any]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP) as connection:
            connection.connect((host, port))
            connection.sendall(b"reference request\n")
            response = connection.recv(64)
        return {"allowed": True, "errno": None, "response": response.decode("ascii")}
    except OSError as error:
        return {"allowed": False, "errno": error.errno}


def execute_reference_handler(
    capability: CapabilityRecord, arguments: Mapping[str, str]
) -> dict[str, Any]:
    """Perform actual open/connect syscalls; no Python policy check emulates denials."""
    output_path = str(capability.workspace / arguments.get("output_name", "record.txt"))
    report: dict[str, Any] = {"environment": sorted(os.environ)}
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            if os.write(descriptor, REFERENCE_CONTENT) != len(REFERENCE_CONTENT):
                raise OSError("incomplete_reference_write")
        finally:
            os.close(descriptor)
        report["workspace_write"] = {"allowed": True, "errno": None}
    except OSError as error:
        report["workspace_write"] = {"allowed": False, "errno": error.errno}
    report["workspace_read"] = _read_record(output_path)
    report["outside_open"] = _read_record(arguments["outside_path"])
    report["audience_connect"] = _connect_resource(
        capability.audience_host, capability.audience_port
    )
    report["other_connect"] = _connect_resource(
        arguments["other_host"], int(arguments["other_port"])
    )
    if arguments.get("metadata_probe", "no") == "yes":
        report["metadata_connect"] = _connect_resource("169.254.169.254", 80)
    if arguments.get("execution_probe", "no") == "yes":
        try:
            # Fixed syscall probe; the confined process must receive a denial.
            os.execve("/bin/true", ["/bin/true"], {})  # noqa: S606 # nosec B606
        except OSError as error:
            report["execution"] = {"allowed": False, "errno": error.errno}
    return report
