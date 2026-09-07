"""Trusted one-process bootstrap; it never invokes a handler before confinement."""

import array
import ctypes
import errno
import json
import os
import resource
import socket
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from confined_tool_execution.handler import execute_reference_handler
from confined_tool_execution.linux import ConfinementUnavailable, confine_process
from confined_tool_execution.models import CapabilityRecord


def main() -> None:
    control = socket.socket(fileno=int(sys.argv[1]))
    initialized = False
    try:
        document = json.loads(control.recv(131072))
        capability = CapabilityRecord(
            **{**document["capability"], "workspace": Path(document["capability"]["workspace"])}
        )
        os.chdir(capability.workspace)
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
        workspace_descriptor = os.open(capability.workspace, os.O_PATH | os.O_DIRECTORY)
        verification_memory = ctypes.create_string_buffer(b"confinement")
        verification_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        listener_descriptor, support = confine_process(workspace_descriptor, control.fileno())
        initialized = True
        ready = {
            "state": "ready",
            "support": asdict(support),
            "verification_address": ctypes.addressof(verification_memory),
            "verification_descriptor": verification_socket.fileno(),
        }
        control.sendmsg(
            [json.dumps(ready).encode()],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener_descriptor]))],
        )
        os.close(listener_descriptor)
        os.close(workspace_descriptor)
        if control.recv(16) != b"execute":
            os._exit(2)
        verification_socket.close()
        if document["procedure"] == "probe":
            descriptor = os.open("verification_record", os.O_WRONLY | os.O_CREAT, 0o600)
            os.write(descriptor, b"verification")
            os.close(descriptor)
            descriptor = os.open("verification_record", os.O_RDONLY)
            if os.read(descriptor, 12) != b"verification":
                raise RuntimeError("workspace_descriptor_injection_failed")
            os.close(descriptor)
            try:
                os.open("/etc/passwd", os.O_RDONLY)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EPERM}:
                    raise RuntimeError("unexpected_probe_denial") from error
            else:
                raise RuntimeError("probe_not_confined")
            report: dict[str, Any] = {"notification_roundtrip": True}
        else:
            report = execute_reference_handler(capability, document["arguments"])
        payload = json.dumps({"state": "complete", "report": report}).encode() + b"\n"
        if os.write(1, payload) != len(payload):
            os._exit(3)
        os._exit(0)
    except BaseException as error:
        response = {
            "state": "unavailable" if isinstance(error, ConfinementUnavailable) else "failed",
            "error": str(error)[:2048],
        }
        if not initialized:
            control.send(json.dumps(response).encode())
        else:
            os.write(1, json.dumps(response).encode() + b"\n")
        os._exit(2)


if __name__ == "__main__":
    main()
