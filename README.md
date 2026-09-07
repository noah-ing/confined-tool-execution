# Confined Tool Execution

This independent Linux reference implementation confines one tool process to the workspace and numeric IPv4 TCP audience named by an already-authorized capability record. After a trusted interpreter imports the fixed handler and applies restrictions, mediated filesystem opens must remain beneath that workspace and connects must match the audience address and port. The supervisor emits and flushes a structured denial record before replying to a denied request; a recording failure terminates execution. The supported configuration requires Landlock ABI 3 or later, libseccomp 2.6.1 or later, and the supervisor access needed for syscall notification mediation. Unavailable enforcement fails closed.

## Scope

This is not a production sandbox, container runtime, virtual machine, hypervisor, or protection against a kernel exploit. It is not a replacement for gVisor or bubblewrap product use. It supports one fixed Python handler in one confined process, with no additional processes or threads, DNS, IPv6, UDP, or audience credentials. The capability is supplied by a trusted caller; this repository does not issue it or establish that redemption occurred. See [scope](docs/scope.md) and the [threat model](docs/threat_model.md).

## Related work

[attested-capability-broker](https://github.com/noah-ing/attested-capability-broker) studies issuance, [resource-bound-authorization](https://github.com/noah-ing/resource-bound-authorization) confines use at the resource, and this repository confines the process that runs the tool.

## Reproduction procedure

Use Python 3.11–3.13 on Linux with the required kernel interfaces and supervisor permissions. macOS and Windows cannot run the kernel-enforced path; portable policy tests remain available there. From a clean checkout:

```sh
uv sync --frozen --extra verification
uv run --frozen python -m examples.unrestricted_demonstration.procedure
uv run --frozen python -m examples.confined_execution.procedure
```

The examples generate a workspace, a sibling file, and two loopback TCP listeners. They require no operational credentials or public service. Phase A demonstrates access to those generated fixtures outside the capability. Phase B requires enforcement and denial records.

The optional Compose verification environment runs preflight, the complete test suite, and both phases:

```sh
docker compose build verification
docker compose run --rm verification
docker compose down
```

To run either phase individually in that environment:

```sh
docker compose run --rm verification python -m examples.unrestricted_demonstration.procedure
docker compose run --rm verification python -m examples.confined_execution.procedure
```

The verification container runs as UID 10000 with `network_mode: none`, a read-only root filesystem, and a temporary `/tmp`. Only local loopback fixtures are reachable. Its outer seccomp profile is `unconfined`, and `SYS_PTRACE` is its only added capability, allowing the supervisor to inspect and duplicate descriptors from its own child. The child then installs this reference's restrictive seccomp policy. These settings support the supervisor experiment; they are not a production deployment recommendation. The image builds libseccomp 2.6.1 from a checksum-pinned source release.

For host verification:

```sh
uv run --frozen pytest
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src/confined_tool_execution
uv run --frozen bandit -q -r src examples
uv run --frozen pip-audit
```

Ordinary host tests marked `linux_confinement` report explicit skips when the required enforcement cannot run. A passing portable suite does not establish kernel confinement. `scripts/verify_linux.py`, the container's default command, first exercises the complete confinement mechanism and then runs tests with `CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL=1`; unavailable enforcement is a failure in that mode. See the [audit procedure](docs/audit_procedure.md) for the evidence boundary.

## Phase A: unrestricted demonstration

The fixed handler runs without restrictions only in the example process. It can read the generated sibling file and connect to the generated non-audience loopback listener. This is a local synthetic control for the subsequent comparison. Its fresh interpreter receives a clean environment, and the example removes any environment additions made by host runtime initialization before invoking the handler. That cleanup is not kernel confinement. No library option disables confinement, and the example exposes no public listener.

## Phase B: confined execution

The same handler runs through `execute_confined(...)`. A fresh interpreter receives a clean environment and no arbitrary inherited descriptors. After trusted initialization, the child applies Landlock and a strict seccomp filter. The supervisor handles notified opens beneath a pre-opened workspace using `openat2` resolution restrictions and returns permitted descriptors with seccomp `ADDFD`. For a connect, it duplicates the child's socket with `pidfd_getfd` and connects only to the exact numeric IPv4 audience. It does not resume pointer-bearing syscalls using `CONTINUE`.

The workspace must be trusted and free from hostile concurrent mutation. Permitted existing objects are owned regular files with a single hard link, or owned directories opened for reading; special files, other owners, symlinks, and mount crossings are rejected. The supervisor checks a regular file before applying requested truncation.

The procedure requires workspace read/write and audience connect to succeed. Outside-workspace opens, non-audience connects, the link-local metadata target, and additional execution must be denied and recorded. The child environment contains only `LC_ALL`. Denial records are JSON lines containing `timestamp`, `principal_id`, `capability_id`, `operation`, `target`, `result`, and `errno`. The confined example writes denial lines to stderr and its final report to stdout; unavailable enforcement produces an explicit result and exits with status 2.

## Deferred work

Arbitrary native-code confinement, production deployment, multiple processes or threads, DNS, IPv6, UDP, credential injection, general resource-quota management, distributed audit collection, and integration with a capability issuer or redemption service are deferred. The reference's fixed deadlines and resource limits are documented in [scope](docs/scope.md). Landlock, seccomp, and unshare are implementation mechanisms, not the claim; this implementation has no weaker fallback when its required mechanisms are unavailable.

Follow the [security policy](SECURITY.md) for private reporting. Licensed under [MIT](LICENSE).
