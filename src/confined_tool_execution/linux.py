"""Linux interfaces used by the confined execution supervisor and child.

The child installs Landlock and a libseccomp filter after trusted initialization.
The supervisor emulates notified operations using copied arguments. This module
never authorizes a notification with ``SECCOMP_USER_NOTIF_FLAG_CONTINUE``.

Calling the restriction functions changes the calling process irreversibly.
They belong in the disposable child, never in the application supervisor.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import socket
from dataclasses import dataclass
from functools import lru_cache

if os.name != "nt":
    import fcntl


class ConfinementUnavailable(RuntimeError):
    """A required Linux interface or supported library is unavailable."""


@dataclass(frozen=True)
class KernelSupport:
    """Versions observed before entering process confinement."""

    landlock_abi: int
    libseccomp_version: str


@dataclass(frozen=True)
class Notification:
    """Copied scalar fields of one outstanding seccomp notification."""

    identifier: int
    process_id: int
    syscall_name: str
    arguments: tuple[int, ...]


class _RulesetAttribute(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathAttribute(ctypes.Structure):
    # The Linux UAPI marks this structure packed: its ABI size is 12 bytes.
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _LibraryVersion(ctypes.Structure):
    _fields_ = [
        ("major", ctypes.c_uint),
        ("minor", ctypes.c_uint),
        ("micro", ctypes.c_uint),
    ]


class _ArgumentComparison(ctypes.Structure):
    _fields_ = [
        ("argument", ctypes.c_uint),
        ("operation", ctypes.c_int),
        ("first_value", ctypes.c_uint64),
        ("second_value", ctypes.c_uint64),
    ]


class _SyscallData(ctypes.Structure):
    _fields_ = [
        ("number", ctypes.c_int),
        ("architecture", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("arguments", ctypes.c_uint64 * 6),
    ]


class _NotificationStructure(ctypes.Structure):
    _fields_ = [
        ("identifier", ctypes.c_uint64),
        ("process_id", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", _SyscallData),
    ]


class _NotificationResponse(ctypes.Structure):
    _fields_ = [
        ("identifier", ctypes.c_uint64),
        ("result", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class _DescriptorInjection(ctypes.Structure):
    _fields_ = [
        ("identifier", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("source_descriptor", ctypes.c_uint32),
        ("destination_descriptor", ctypes.c_uint32),
        ("destination_flags", ctypes.c_uint32),
    ]


class _MemoryVector(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class _OpenAttribute(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


_NOTIFICATION_SYSCALLS = (
    "open",
    "openat",
    "openat2",
    "creat",
    "connect",
    "execve",
    "execveat",
)

# This is an allowlist, not an enumeration of dangerous system calls. In
# particular, process creation, new execution, descriptor duplication, socket
# families other than IPv4 TCP, io_uring, tracing, and filter replacement have
# no permission here. Path-based metadata operations are also not allowed.
_ORDINARY_SYSCALLS = (
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "fstat",
    "lseek",
    "ftruncate",
    "fsync",
    "fdatasync",
    "recvfrom",
    "getsockopt",
    "getsockname",
    "getpeername",
    "shutdown",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create1",
    "epoll_ctl",
    "epoll_wait",
    "epoll_pwait",
    "brk",
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "madvise",
    "futex",
    "sched_yield",
    "clock_gettime",
    "clock_getres",
    "clock_nanosleep",
    "gettimeofday",
    "time",
    "nanosleep",
    "getrandom",
    "getpid",
    "getppid",
    "gettid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "rt_sigreturn",
    "restart_syscall",
    "exit",
    "exit_group",
)

_ACTION_ALLOW = 0x7FFF0000
_ACTION_NOTIFY = 0x7FC00000
_ACTION_DENY = 0x00050000 | errno.EPERM
_COMPARE_EQUAL = 4
_COMPARE_MASKED_EQUAL = 7
_DESCRIPTOR_INJECTION_SEND = 2
_UNAVAILABLE_ERROR_NUMBERS = frozenset({errno.ENOSYS, errno.EOPNOTSUPP, errno.EPERM, errno.EACCES})


def _require_linux() -> None:
    if platform.system() != "Linux":
        raise ConfinementUnavailable("process confinement requires Linux")
    if platform.machine() not in {"x86_64", "aarch64"}:
        raise ConfinementUnavailable("the Linux reference supports x86_64 and aarch64 only")


@lru_cache(maxsize=1)
def _system_library() -> ctypes.CDLL:
    _require_linux()
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    library.prctl.restype = ctypes.c_int
    library.ioctl.restype = ctypes.c_int
    library.process_vm_readv.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_MemoryVector),
        ctypes.c_ulong,
        ctypes.POINTER(_MemoryVector),
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    library.process_vm_readv.restype = ctypes.c_ssize_t
    return library


@lru_cache(maxsize=1)
def _seccomp_library() -> ctypes.CDLL:
    _require_linux()
    # Prefer the administrator-installed standard local prefix used by the
    # verification image. Its pinned release may coexist with an older distro
    # SONAME selected by the dynamic loader. Both locations belong to trusted
    # operating-system initialization; no child environment selects this path.
    local_library = "/usr/local/lib/libseccomp.so.2"
    library_path = local_library if os.path.exists(local_library) else "libseccomp.so.2"
    try:
        library = ctypes.CDLL(library_path, use_errno=True)
    except OSError as error:
        raise ConfinementUnavailable("libseccomp.so.2 is required") from error
    library.seccomp_version.argtypes = []
    library.seccomp_version.restype = ctypes.POINTER(_LibraryVersion)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_release.restype = None
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_ArgumentComparison),
    ]
    library.seccomp_rule_add_array.restype = ctypes.c_int
    library.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
    library.seccomp_notify_fd.restype = ctypes.c_int
    library.seccomp_notify_alloc.argtypes = [
        ctypes.POINTER(ctypes.POINTER(_NotificationStructure)),
        ctypes.POINTER(ctypes.POINTER(_NotificationResponse)),
    ]
    library.seccomp_notify_alloc.restype = ctypes.c_int
    library.seccomp_notify_free.argtypes = [
        ctypes.POINTER(_NotificationStructure),
        ctypes.POINTER(_NotificationResponse),
    ]
    library.seccomp_notify_free.restype = None
    library.seccomp_notify_receive.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_NotificationStructure),
    ]
    library.seccomp_notify_receive.restype = ctypes.c_int
    library.seccomp_notify_respond.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(_NotificationResponse),
    ]
    library.seccomp_notify_respond.restype = ctypes.c_int
    library.seccomp_notify_id_valid.argtypes = [ctypes.c_int, ctypes.c_uint64]
    library.seccomp_notify_id_valid.restype = ctypes.c_int
    version = library.seccomp_version().contents
    observed = (int(version.major), int(version.minor), int(version.micro))
    if observed < (2, 6, 1):
        raise ConfinementUnavailable(
            "libseccomp 2.6.1 or later is required; found "
            + ".".join(str(component) for component in observed)
        )
    return library


def _raise_system_error(operation: str) -> None:
    error_number = ctypes.get_errno()
    raise OSError(error_number, f"{operation}: {os.strerror(error_number)}")


def _check_library_result(result: int, operation: str) -> None:
    if result < 0:
        error_number = -result
        # Notification receive/respond map kernel errors to ECANCELED while
        # retaining errno. Preserve interruptions and expired notifications.
        if error_number == errno.ECANCELED:
            error_number = ctypes.get_errno() or error_number
        raise OSError(error_number, f"{operation}: {os.strerror(error_number)}")


def _raise_if_unavailable(error: OSError, mechanism: str) -> None:
    if error.errno in _UNAVAILABLE_ERROR_NUMBERS:
        raise ConfinementUnavailable(
            f"{mechanism} unavailable: errno={error.errno}: {error.strerror}"
        ) from error


def _landlock_abi() -> int:
    # These three syscall numbers are shared by both supported architectures.
    result = int(
        _system_library().syscall(
            ctypes.c_long(444),
            ctypes.c_void_p(),
            ctypes.c_size_t(0),
            ctypes.c_uint(1),  # LANDLOCK_CREATE_RULESET_VERSION
        )
    )
    if result < 0:
        error_number = ctypes.get_errno()
        error = OSError(error_number, f"Landlock ABI query: {os.strerror(error_number)}")
        _raise_if_unavailable(error, "Landlock ABI query")
        raise error
    if result < 3:
        raise ConfinementUnavailable(f"Landlock ABI 3 or later is required; found ABI {result}")
    return result


def load_kernel_support() -> KernelSupport:
    """Check versions; actual notification/ptrace permission needs a probe."""
    _require_linux()
    library = _seccomp_library()
    version = library.seccomp_version().contents
    return KernelSupport(
        landlock_abi=_landlock_abi(),
        libseccomp_version=f"{version.major}.{version.minor}.{version.micro}",
    )


def restrict_workspace(workspace_descriptor: int) -> int:
    """Restrict this child to regular-file access beneath its workspace."""
    abi = _landlock_abi()
    system_library = _system_library()
    # Handle every filesystem access right defined through the observed ABI.
    # Access is denied unless the one workspace rule explicitly grants it.
    handled_access = (1 << 15) - 1  # ABI 3 includes REFER and TRUNCATE.
    if abi >= 5:
        handled_access |= 1 << 15  # IOCTL_DEV
    if abi >= 9:
        handled_access |= 1 << 16  # RESOLVE_UNIX
    ruleset_attribute = _RulesetAttribute(handled_access_fs=handled_access)
    ruleset_descriptor = int(
        system_library.syscall(
            ctypes.c_long(444),
            ctypes.byref(ruleset_attribute),
            ctypes.c_size_t(ctypes.sizeof(ruleset_attribute)),
            ctypes.c_uint(0),
        )
    )
    if ruleset_descriptor < 0:
        _raise_system_error("landlock_create_ruleset")
    try:
        # READ_FILE | WRITE_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE |
        # MAKE_DIR | MAKE_REG | REFER | TRUNCATE. No execute, special-file,
        # symlink creation, device ioctl, or UNIX socket permission is granted.
        allowed_access = sum(1 << bit for bit in (1, 2, 3, 4, 5, 7, 8, 13, 14))
        path_attribute = _PathAttribute(
            allowed_access=allowed_access,
            parent_fd=workspace_descriptor,
        )
        result = int(
            system_library.syscall(
                ctypes.c_long(445),
                ctypes.c_int(ruleset_descriptor),
                ctypes.c_int(1),  # LANDLOCK_RULE_PATH_BENEATH
                ctypes.byref(path_attribute),
                ctypes.c_uint(0),
            )
        )
        if result < 0:
            _raise_system_error("landlock_add_rule")
        result = int(
            system_library.prctl(
                ctypes.c_int(38),  # PR_SET_NO_NEW_PRIVS
                ctypes.c_ulong(1),
                ctypes.c_ulong(0),
                ctypes.c_ulong(0),
                ctypes.c_ulong(0),
            )
        )
        if result < 0:
            _raise_system_error("PR_SET_NO_NEW_PRIVS")
        result = int(
            system_library.syscall(
                ctypes.c_long(446),
                ctypes.c_int(ruleset_descriptor),
                ctypes.c_uint(0),
            )
        )
        if result < 0:
            _raise_system_error("landlock_restrict_self")
    finally:
        os.close(ruleset_descriptor)
    return abi


def _add_rule(
    library: ctypes.CDLL,
    context: int,
    name: str,
    action: int,
    comparisons: tuple[_ArgumentComparison, ...] = (),
) -> None:
    syscall_number = int(library.seccomp_syscall_resolve_name(name.encode("ascii")))
    # aarch64 has no native open(), creat(), select(), etc. Their native
    # replacements are covered; a negative pseudo-number cannot be invoked.
    if syscall_number < 0:
        return
    comparison_array = (_ArgumentComparison * len(comparisons))(*comparisons)
    result = int(
        library.seccomp_rule_add_array(
            context,
            action,
            syscall_number,
            len(comparisons),
            comparison_array,
        )
    )
    _check_library_result(result, f"seccomp rule for {name}")


def _comparison(
    argument: int, value: int, *, operation: int = _COMPARE_EQUAL
) -> _ArgumentComparison:
    return _ArgumentComparison(
        argument=argument,
        operation=operation,
        first_value=value,
        second_value=0,
    )


def restrict_egress(control_descriptor: int) -> int:
    """Install the child syscall allowlist and return its notification fd.

    The control descriptor must remain open until process exit. It is the only
    descriptor allowed to send SCM_RIGHTS during trusted listener transfer;
    its number cannot be closed or replaced under this filter. The supervisor
    must never return descriptors over this channel.
    """
    if not 0 <= control_descriptor < (1 << 31):
        raise ValueError("control descriptor must be a nonnegative Linux int")
    library = _seccomp_library()
    context_value = library.seccomp_init(_ACTION_DENY)
    if context_value is None:
        raise ConfinementUnavailable("libseccomp could not allocate a filter")
    context = int(context_value)
    try:
        for name in _ORDINARY_SYSCALLS:
            _add_rule(library, context, name, _ACTION_ALLOW)
        for name in _NOTIFICATION_SYSCALLS:
            _add_rule(library, context, name, _ACTION_NOTIFY)
        # close() consumes an int. Match inequality in its low 32 bits, so
        # alternative high bits cannot select the reserved control descriptor.
        # libseccomp permits each argument to be compared once per rule; the
        # union of differing-bit rules expresses this masked inequality.
        for bit in range(32):
            mask = 1 << bit
            different_bit = 0 if control_descriptor & mask else mask
            descriptor_comparison = _ArgumentComparison(
                argument=0,
                operation=_COMPARE_MASKED_EQUAL,
                first_value=mask,
                second_value=different_bit,
            )
            _add_rule(library, context, "close", _ACTION_ALLOW, (descriptor_comparison,))
        for command in (fcntl.F_GETFD, fcntl.F_SETFD, fcntl.F_GETFL):
            _add_rule(
                library,
                context,
                "fcntl",
                _ACTION_ALLOW,
                (_comparison(1, command),),
            )
        # Linux SOCK_CLOEXEC equals O_CLOEXEC on both supported architectures.
        for socket_type in (socket.SOCK_STREAM, socket.SOCK_STREAM | os.O_CLOEXEC):
            for protocol in (0, socket.IPPROTO_TCP):
                _add_rule(
                    library,
                    context,
                    "socket",
                    _ACTION_ALLOW,
                    (
                        _comparison(0, socket.AF_INET),
                        _comparison(1, socket_type),
                        _comparison(2, protocol),
                    ),
                )
        _add_rule(
            library,
            context,
            "sendto",
            _ACTION_ALLOW,
            (_comparison(4, 0), _comparison(5, 0)),
        )
        _add_rule(
            library,
            context,
            "sendmsg",
            _ACTION_ALLOW,
            (_comparison(0, control_descriptor),),
        )
        result = int(library.seccomp_load(context))
        _check_library_result(result, "seccomp_load")
        listener_descriptor = int(library.seccomp_notify_fd(context))
        _check_library_result(listener_descriptor, "seccomp_notify_fd")
        return listener_descriptor
    finally:
        library.seccomp_release(context)


def confine_process(
    workspace_descriptor: int, control_descriptor: int
) -> tuple[int, KernelSupport]:
    """Apply both mandatory mechanisms in the initialized disposable child."""
    support = load_kernel_support()
    try:
        thread_count = len(os.listdir("/proc/self/task"))
    except OSError as error:
        raise ConfinementUnavailable("cannot verify the single-thread process") from error
    if thread_count != 1:
        raise ConfinementUnavailable("confinement requires a single-thread process")
    try:
        restrict_workspace(workspace_descriptor)
    except OSError as error:
        _raise_if_unavailable(error, "Landlock installation")
        raise
    try:
        listener_descriptor = restrict_egress(control_descriptor)
    except OSError as error:
        _raise_if_unavailable(error, "seccomp installation")
        raise
    return listener_descriptor, support


@lru_cache(maxsize=1)
def _notification_names() -> dict[int, str]:
    library = _seccomp_library()
    names: dict[int, str] = {}
    for name in _NOTIFICATION_SYSCALLS:
        number = int(library.seccomp_syscall_resolve_name(name.encode("ascii")))
        if number >= 0:
            names[number] = name
    return names


def get_notification(listener_descriptor: int) -> Notification:
    """Receive one event after the caller observes listener readability."""
    library = _seccomp_library()
    request = ctypes.POINTER(_NotificationStructure)()
    response = ctypes.POINTER(_NotificationResponse)()
    result = int(library.seccomp_notify_alloc(ctypes.byref(request), ctypes.byref(response)))
    _check_library_result(result, "seccomp_notify_alloc")
    try:
        result = int(library.seccomp_notify_receive(listener_descriptor, request))
        _check_library_result(result, "seccomp_notify_receive")
        structure = request.contents
        return Notification(
            identifier=int(structure.identifier),
            process_id=int(structure.process_id),
            syscall_name=_notification_names().get(int(structure.data.number), "unknown"),
            arguments=tuple(int(argument) for argument in structure.data.arguments),
        )
    finally:
        library.seccomp_notify_free(request, response)


def send_notification_result(
    listener_descriptor: int,
    identifier: int,
    *,
    result: int = 0,
    error_number: int = 0,
) -> None:
    """Return a supervisor result without executing the original syscall."""
    if not 0 <= error_number <= 4095:
        raise ValueError("error number must be between zero and 4095")
    if not -(1 << 63) <= result < (1 << 63):
        raise ValueError("result does not fit a signed 64-bit integer")
    library = _seccomp_library()
    request = ctypes.POINTER(_NotificationStructure)()
    response = ctypes.POINTER(_NotificationResponse)()
    allocation_result = int(
        library.seccomp_notify_alloc(ctypes.byref(request), ctypes.byref(response))
    )
    _check_library_result(allocation_result, "seccomp_notify_alloc")
    try:
        response.contents.identifier = identifier
        response.contents.result = result
        response.contents.error = -error_number
        response.contents.flags = 0
        response_result = int(library.seccomp_notify_respond(listener_descriptor, response))
        _check_library_result(response_result, "seccomp_notify_respond")
    finally:
        library.seccomp_notify_free(request, response)


def inject_descriptor(listener_descriptor: int, identifier: int, descriptor: int) -> int:
    """Atomically inject an opened descriptor and finish its notification."""
    _require_linux()
    if descriptor < 0:
        raise ValueError("source descriptor must be nonnegative")
    injection = _DescriptorInjection(
        identifier=identifier,
        flags=_DESCRIPTOR_INJECTION_SEND,
        source_descriptor=descriptor,
        destination_descriptor=0,
        destination_flags=os.O_CLOEXEC,
    )
    # _IOW('!', 3, struct seccomp_notif_addfd), identical on supported ABIs.
    request_number = (1 << 30) | (ctypes.sizeof(injection) << 16) | (ord("!") << 8) | 3
    result = int(
        _system_library().ioctl(
            ctypes.c_int(listener_descriptor),
            ctypes.c_ulong(request_number),
            ctypes.byref(injection),
        )
    )
    if result < 0:
        _raise_system_error("SECCOMP_IOCTL_NOTIF_ADDFD")
    return result


def notification_valid(listener_descriptor: int, identifier: int) -> bool:
    """Return whether this notification still identifies a blocked syscall."""
    result = int(_seccomp_library().seccomp_notify_id_valid(listener_descriptor, identifier))
    if result == -errno.ENOENT:
        return False
    _check_library_result(result, "seccomp_notify_id_valid")
    return True


def copy_process_bytes(process_id: int, address: int, length: int) -> bytes:
    """Copy one bounded byte range; partial reads are errors, never evidence."""
    if process_id <= 0 or address <= 0:
        raise OSError(errno.EFAULT, "invalid process memory address")
    if not 0 <= length <= 65536:
        raise ValueError("process memory copy must be between zero and 65536 bytes")
    if address + length > (1 << 64):
        raise OSError(errno.EFAULT, "process memory range overflows")
    if length == 0:
        return b""
    destination = ctypes.create_string_buffer(length)
    local_vector = _MemoryVector(ctypes.addressof(destination), length)
    remote_vector = _MemoryVector(address, length)
    copied_length = int(
        _system_library().process_vm_readv(
            process_id,
            ctypes.byref(local_vector),
            1,
            ctypes.byref(remote_vector),
            1,
            0,
        )
    )
    if copied_length < 0:
        _raise_system_error("process_vm_readv")
    if copied_length != length:
        raise OSError(errno.EFAULT, "incomplete process memory copy")
    return bytes(destination.raw)


def copy_process_string(process_id: int, address: int, maximum_bytes: int = 4096) -> str:
    """Read a bounded NUL-terminated path without crossing pages speculatively."""
    _require_linux()
    if not 1 <= maximum_bytes <= 65536:
        raise ValueError("maximum string size must be between one and 65536 bytes")
    page_size = int(os.sysconf("SC_PAGE_SIZE"))
    copied = bytearray()
    while len(copied) < maximum_bytes:
        current_address = address + len(copied)
        length = min(
            maximum_bytes - len(copied),
            page_size - current_address % page_size,
            256,
        )
        part = copy_process_bytes(process_id, current_address, length)
        terminator = part.find(b"\0")
        if terminator >= 0:
            copied.extend(part[:terminator])
            return os.fsdecode(bytes(copied))
        copied.extend(part)
    raise OSError(errno.ENAMETOOLONG, "process string exceeds its bound")


def duplicate_process_descriptor(process_descriptor: int, descriptor: int) -> int:
    """Duplicate a child descriptor; ptrace and outer seccomp checks apply."""
    if process_descriptor < 0 or descriptor < 0:
        raise OSError(errno.EBADF, "invalid descriptor")
    result = int(
        _system_library().syscall(
            ctypes.c_long(438),  # pidfd_getfd
            ctypes.c_int(process_descriptor),
            ctypes.c_int(descriptor),
            ctypes.c_uint(0),
        )
    )
    if result < 0:
        _raise_system_error("pidfd_getfd")
    return result


def open_workspace_descriptor(
    workspace_descriptor: int, relative_path: str, flags: int, mode: int
) -> int:
    """Open beneath the pinned workspace without truncating an unchecked file.

    The supervisor validates request flags before calling, then checks the
    returned descriptor type and ownership before any requested truncation.
    Nonblocking mode prevents special-file opens from stalling that check.
    """
    _require_linux()
    if not relative_path or os.path.isabs(relative_path) or "\0" in relative_path:
        raise OSError(errno.EACCES, "workspace path must be relative and nonempty")
    encoded_path = os.fsencode(relative_path)
    if len(encoded_path) >= 4096:
        raise OSError(errno.ENAMETOOLONG, "workspace path exceeds its bound")
    if flags < 0 or mode < 0 or flags >= (1 << 64) or mode >= (1 << 64):
        raise OSError(errno.EINVAL, "invalid open flags or mode")
    open_flags = (flags & ~os.O_TRUNC) | os.O_CLOEXEC
    # O_PATH performs object inspection without opening a device for I/O.
    # openat2 rejects O_NONBLOCK combined with O_PATH.
    if not flags & os.O_PATH:
        open_flags |= os.O_NONBLOCK
    # RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH. NO_SYMLINKS
    # includes NO_MAGICLINKS and avoids any need for userspace realpath checks.
    attributes = _OpenAttribute(flags=open_flags, mode=mode, resolve=0x01 | 0x04 | 0x08)
    result = int(
        _system_library().syscall(
            ctypes.c_long(437),  # openat2
            ctypes.c_int(workspace_descriptor),
            ctypes.c_char_p(encoded_path),
            ctypes.byref(attributes),
            ctypes.c_size_t(ctypes.sizeof(attributes)),
        )
    )
    if result < 0:
        _raise_system_error("openat2")
    return result
