# Threat model

## Assurance statement

For the supported Linux configuration, one fixed tool handler runs with a capability-defined workspace and numeric IPv4 TCP audience. Its supported file opens and connects pass through supervisor mediation after the child installs its restrictions. A denied mediated operation is recorded before the child receives a denial. Failure to establish confinement or record a denial must not produce an unrestricted successful execution.

This is process authority restriction for a bounded reference workload. It does not establish kernel isolation against arbitrary native code, capability authenticity, prior redemption, exactly-once business execution, or production availability.

## Trusted computing base

The reference trusts the Linux kernel, enabled Landlock implementation, seccomp and descriptor-management interfaces, libseccomp, Python interpreter and loaded modules, supervisor, fixed handler initialization, capability policy, and denial-record destination. It also trusts the parent host and filesystem topology at setup.

The supervisor remains outside the child's Landlock domain because it must resolve approved operations and write records. Its correctness and privileges are therefore part of enforcement, not an independent isolation guarantee. The fresh interpreter's environment, initial descriptors, module imports, and restriction order must be reviewed as one boundary.

## Capability and initialization

The caller authorizes the local capability before execution. The execution layer checks the selected tool and argument binding against that record. Principal and capability identifiers provide record attribution supplied by the caller; they are not new identity or issuance proofs.

The supervisor creates a fresh Python interpreter, supplies a clean environment, and closes arbitrary inherited descriptors. The fixed handler and required runtime modules are imported before restrictions. No untrusted plugin-loading or import-time execution is within the assurance claim. There is one confined process and no additional processes or threads.

## Filesystem boundary

The child's Landlock policy limits its filesystem authority. Notified open operations are resolved by the supervisor against a workspace directory descriptor using `openat2` with beneath-only, no-symlink, and no-mount-crossing resolution. The supervisor injects the resulting permitted descriptor through seccomp `ADDFD`; it does not tell the kernel to repeat an unchecked child path lookup.

The reference does not rely on a string-prefix comparison alone. It excludes symlinks and crossing into other mounts even when they appear below the workspace path. Preexisting workspace contents and any authority intentionally embodied in those files remain the caller's responsibility. The configured workspace is trusted input, not a directory selected by the handler.

Existing objects are first inspected using `O_PATH`, avoiding a device's open operation. The supervisor rejects special files, regular files with multiple hard links, and objects owned by another user; it checks the resulting descriptor again before truncating a permitted regular file. Owned directories are supported only for read opens. These checks require a trusted workspace without hostile concurrent mutation. They are not an atomic defense against an external actor changing object identity or ownership between inspection and use.

## Network boundary

The audience is a numeric IPv4 address and TCP port. The supervisor reads the notified connect request, verifies the address family and exact target, duplicates the child's socket through `pidfd_getfd`, and performs the permitted connect on that duplicate. It never uses seccomp `CONTINUE` to resume an approved pointer-bearing connect or open syscall.

The filter excludes unsupported socket and process behavior. DNS, IPv6, UDP, network namespaces as a fallback, and endpoint credential injection are outside scope. Link-local metadata and non-audience targets must be rejected before a connection is made. Tests use generated loopback listeners for positive and negative controls; no public service is needed.

## Denial and termination boundary

The supervisor constructs a structured record for a denied mediated open, connect, or execution attempt, writes it to the configured stream, and flushes it before replying. The record identifies the principal, capability, operation, target, timestamp, denied result, and error number when available. An output failure terminates the execution instead of returning an unrecorded denial as a normal outcome.

This describes the application's record ordering. It does not guarantee durable delivery if the host fails, authenticate the records, or cover every possible kernel error and process termination with an operation-specific record. Broad syscall rejection and fatal runtime failure are distinct from the recorded mediated decisions. Exceeding the configured deadline, notification limit, report bound, or child resource limits can terminate the process without completing its intended work.

## Host and container assumptions

Supervisor access to the child is subject to Linux ptrace-style permission checks. The verification container runs as UID 10000, disables its outer seccomp filter, and adds only `SYS_PTRACE` after dropping other capabilities. It has no external network, a read-only root filesystem, and a temporary `/tmp`. The child still must establish its own Landlock and seccomp restrictions. A container startup or capability assignment is not a passing confinement test.

The preflight exercises workspace descriptor injection and a denied open, and verifies actual parent memory-read and descriptor-duplication permission. In required Linux verification mode, unavailable support fails the run rather than skipping the enforced tests. Ordinary portable tests may skip with an explicit reason; those skips supply no evidence about kernel behavior.

The threat model excludes kernel exploitation, a compromised supervisor or host administrator, arbitrary hostile native code, side channels, and comprehensive resource-exhaustion resistance. It does not promise that the process remains useful after every denied syscall. Refer to [scope](scope.md) for the complete supported boundary.

## Primary mechanism references

The [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html) describes filesystem rules and ABI negotiation. The [Linux seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html) describes filtering, user notification, and descriptor injection. The Linux manual pages document [`openat2` resolution constraints](https://man7.org/linux/man-pages/man2/openat2.2.html) and [`pidfd_getfd` permission checks](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html). These describe mechanisms; this repository's supported composition and tests define its narrower claim.
