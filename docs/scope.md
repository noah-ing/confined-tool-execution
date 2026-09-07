# Scope

## Supported boundary

The reference accepts a local capability describing a workspace path, numeric IPv4 audience address and TCP port, the fixed `workspace.reference` tool name, and argument digest. A trusted caller supplies that record and the principal and capability identifiers used in denial records. Authenticating the capability, verifying its issuer, and establishing prior redemption are the caller's responsibilities. Python 3.11–3.13 is supported.

The supported workload is one fixed, trivial Python tool handler. A trusted supervisor starts a fresh interpreter with a clean environment and closes arbitrary inherited file descriptors. The interpreter imports the trusted handler before applying restrictions. The claim begins after successful restriction and covers the supported handler operations; it does not cover arbitrary import-time code or arbitrary native extensions.

The confined process can obtain ordinary file access only within the configured workspace and create TCP connections only to the exact numeric IPv4 audience. The execution API has no disabled-confinement flag. The unrestricted comparison exists only under `examples/unrestricted_demonstration/`.

## Required mechanisms

The Linux configuration requires Landlock ABI 3 or later, libseccomp 2.6.1 or later, seccomp user notification and descriptor injection, `openat2`, `process_vm_readv`, and `pidfd_getfd`. The supervisor must have the Linux permissions needed to inspect its child and duplicate the child's socket descriptor.

Landlock restricts the child filesystem domain. The supervisor resolves permitted opens relative to the workspace using `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_XDEV`, then supplies the opened descriptor through seccomp `ADDFD`. Workspace symlinks and mount crossings are outside the supported access model. Network mediation compares a parsed numeric IPv4 address and port with the capability and performs the permitted connect on a duplicate of the child's socket. Pointer-bearing operations are not released with seccomp `CONTINUE`.

Existing workspace objects are inspected with `O_PATH` before the requested open. Special files, regular files with multiple hard links, and objects owned by another user are rejected. Opened objects are checked again; requested truncation is applied only after verifying an owned regular file with one link. Directories support read-only opens. The workspace and its surrounding topology must not be concurrently mutated by a hostile actor. The reference does not claim that the ownership and link-count checks form an atomic transaction with arbitrary external filesystem changes.

The native loader prefers `/usr/local/lib/libseccomp.so.2` when present and otherwise uses the system library. It checks the version in either case and rejects versions older than 2.6.1. The Docker image compiles a checksum-pinned libseccomp 2.6.1 source release; this is not a fallback to an older filter compiler.

Landlock/seccomp/unshare are implementation mechanisms, not the claim. This implementation does not substitute an unshare-based mode or an unrestricted process when its required mechanism is unavailable.

## Explicit exclusions

- Not a production sandbox.
- Not container or VM isolation.
- Not protection against a kernel exploit.
- Not a replacement for gVisor / bubblewrap product use.
- Not general isolation for arbitrary untrusted native code.

macOS and Windows kernel enforcement are out of scope. Their ordinary portable test runs report explicit skips for Linux-enforced tests. When `CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL=1`, unavailable enforcement or a non-Linux platform causes a failure instead of a skip. The confined example fails closed when enforcement is unavailable.

## Environment and network limits

There is one confined child process, with no further processes or threads. DNS resolution, IPv6, UDP, arbitrary socket families, and credential injection are unsupported. The audience is an exact numeric IPv4 address and TCP port, not a hostname, URL, redirect policy, or service identity authenticated by TLS.

The child environment is built as `{"LC_ALL": "C.UTF-8"}` without reading the parent's environment. In particular, `AWS_*`, `AZURE_*`, `GOOGLE_*`, `GITHUB_TOKEN`, and `AUTHORIZATION` are not passed through. The reference supplies no audience credential and makes no claim about a future credential-injection design. Trusted initialization, runtime memory, and the designated control and reporting descriptors remain part of the trusted computing base. Bootstrap descriptors are explicitly tracked and closed; arbitrary parent descriptors do not survive the isolated interpreter launch.

## Execution bounds

The supervisor has a configured 10-second execution deadline, a limit of 64 syscall notifications, and separate 65,536-byte bounds for child stdout and stderr. The child sets a 5-second CPU limit, a 64-descriptor limit, and a 1 MiB file-size limit. These are fixed controls for the reference workload, not general quota accounting, comprehensive denial-of-service resistance, or a guaranteed completion time under every host failure.

## Denial records

Denied mediated opens, connects, and execution attempts produce JSON-line records with `timestamp`, `principal_id`, `capability_id`, `operation`, `target`, `result="denied"`, and `errno` when known. The supervisor writes and flushes the record before replying to the child. If recording fails, it terminates execution. Other fatal failures, including exceeded execution bounds, are not promised an operation-specific denial record.

A stream flush is not a claim of durable storage, an authenticated audit log, or a transaction with external effects. The record destination is chosen by the trusted caller. This repository supplies no metrics pipeline, remote collector, retention policy, or signed evidence format.

## Verification container

The Compose verification service runs under UID 10000 with no external network, a read-only root filesystem, and a temporary `/tmp`. It drops all capabilities and adds only `SYS_PTRACE`; its outer seccomp profile is `unconfined`. Those permissions allow the supervisor's child-inspection operations; the child installs its own restrictive filter. Loopback remains available for generated audience listeners. Container configuration alone is not evidence that child confinement succeeded.

The default command, `scripts/verify_linux.py`, requires a successful `probe_confinement()` before running the test suite and both phases. The probe performs an allowed workspace write/read and a denied outside open, and checks actual `process_vm_readv` and `pidfd_getfd` access. It does not merely read a kernel version string. The script requires the Linux test path through `CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL=1`.

## Deferred work

Production operation, broader handlers and native extensions, additional processes or threads, DNS, IPv6, UDP, credential injection, general quota management, availability against hostile workloads, persistent audit infrastructure, and composition with issuer and redemption services are deferred.
