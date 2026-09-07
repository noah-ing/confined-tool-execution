# Audit procedure

## Review target

Establish whether the fixed handler's supported file and TCP operations are restricted after initialization, whether rejected operations are recorded before reply, and whether unavailable enforcement fails closed. Read [scope](scope.md) and the [threat model](threat_model.md) first.

Record the commit, operating system, kernel and Landlock ABI, libseccomp version, supervisor permission result, commands, failures, and skips. Distinguish portable policy decisions from actual kernel enforcement. A macOS or Windows test run cannot substantiate the Linux confinement claim.

## Source review

Follow `execute_confined(...)` in `src/confined_tool_execution/supervisor.py` from capability and argument validation through child creation, trusted imports, restriction installation, notification mediation, result collection, and termination. Confirm that no installed-library option selects unrestricted execution. `probe_confinement()` must exercise permitted workspace write/read, denied outside access, and actual parent memory-read and descriptor-duplication permission. A version check alone is insufficient.

Review these boundaries:

| Boundary | Required observation |
| --- | --- |
| Initialization | Fresh interpreter, clean environment, arbitrary inherited descriptors closed, trusted imports before restriction |
| Workspace | Landlock applied; `O_PATH` inspection and opened-descriptor checks enforce supported ownership, regular-file/link-count and directory rules; resolution uses `openat2` beneath/no-symlink/no-mount-crossing constraints |
| Descriptor injection | Only supervisor-approved workspace descriptors returned with seccomp `ADDFD` |
| Egress | Exact numeric IPv4 TCP target; the supervisor connects through a duplicate of the child's socket |
| Pointer arguments | No seccomp `CONTINUE` for mediated opens or connects |
| Denial output | JSON record written and flushed before reply; output failure terminates execution |
| Process behavior | Unsupported process creation, threads, and network operations unavailable after restriction |
| Execution bounds | Supervisor deadline, notification and report bounds, and child CPU/descriptor/file-size limits are applied without being presented as general quotas |
| Unrestricted control | Confined to the generated-fixture example; no public listener or library fallback |

Inspect syscall selection and failure branches as well as positive policy decisions. Verify that unsupported syscall forms cannot create an alternate path to the intended operation. Check that requested truncation occurs only after validating the opened regular file. Confirm the documented prerequisite that the workspace is not under hostile concurrent mutation. Do not equate Landlock availability with successful installation of the complete filter and supervisor path.

## Required regression evidence

| Test | Required result |
| --- | --- |
| `test_workspace_open_outside_denied` | Outside-workspace file access is denied under kernel enforcement |
| `test_workspace_open_inside_allowed` | Supported workspace read/write succeeds |
| `test_egress_non_audience_denied` | The generated non-audience listener receives no allowed connection |
| `test_egress_audience_allowed` | The exact configured audience is reachable |
| `test_link_local_metadata_endpoint_denied` | The link-local target is rejected without connecting |
| `test_ambient_credential_names_absent` | Parent credential environment variables are absent in the child |
| `test_denial_record_emitted_on_denied_open` | The rejected open has its structured record |
| `test_denial_record_emitted_on_denied_connect` | The rejected connect has its structured record |
| `test_unrestricted_demonstration_succeeds_when_confinement_disabled` | Only the unrestricted example reaches its generated outside file and non-audience listener |
| `test_library_default_confinement_enabled` | The public execution path requires enforcement and has no disabled mode |

Also review record-output failure, received-descriptor cleanup, and unavailable-kernel behavior. A skip must carry a specific reason and must not be counted as exercised enforcement. `scripts/verify_linux.py` runs preflight and sets `CONFINED_TOOL_EXECUTION_REQUIRE_KERNEL=1` for the suite: a missing Linux enforcement path is then a failure, not a skip.

## Procedures

From the repository root:

```sh
uv sync --frozen --extra verification
uv run --frozen pytest
uv run --frozen ruff check .
uv run --frozen ruff format --check .
uv run --frozen mypy src/confined_tool_execution
uv run --frozen bandit -q -r src examples
uv run --frozen pip-audit
```

Run the comparison on a supported Linux host:

```sh
uv run --frozen python -m examples.unrestricted_demonstration.procedure
uv run --frozen python -m examples.confined_execution.procedure
```

For the mandatory Linux preflight, full suite, and both phases, run:

```sh
uv run --frozen python scripts/verify_linux.py
```

Or use the same default procedure in the verification container:

```sh
docker compose build verification
docker compose run --rm verification
docker compose down
```

Individual container phase commands remain available as `docker compose run --rm verification python -m examples.unrestricted_demonstration.procedure` and `docker compose run --rm verification python -m examples.confined_execution.procedure`.

Inspect the actual exit status, result, and JSON denial records. Phase B writes denial lines to stderr and its final report to stdout; unavailable enforcement must exit with status 2. A successful image build is not confinement evidence. The verification container's outer `seccomp=unconfined` and `SYS_PTRACE` settings enable supervisor operations; verify that the nonroot child subsequently establishes its own restrictive policy. External networking is disabled, while loopback supports the generated listeners.

The Dockerfile pins its Python base-image digest and libseccomp 2.6.1 source checksum. The loader checks libseccomp's version even when it resolves the system library. Distribution build packages and the version-pinned `uv` download prevent this procedure from being a claim of byte-identical image builds. Static typing uses the configured Linux target, including when invoked from a portable host.

The unrestricted example is a control using a generated sibling file and loopback listeners. The confined example must preserve the permitted workspace and audience operations while rejecting the same excess authority. Do not replace either result with a mocked kernel call and present it as an integration result.

## Interpretation and publication

Type checks, Ruff, Bandit, and dependency scanning supplement behavioral evidence; none proves confinement. Advisory scans depend on a current database. Record skips and environmental blockers separately from passed tests.

Inspect publication artifacts for generated private material, local environment contents, unrelated files, and operational credentials. Denial targets may contain local paths, so use only the synthetic fixture output when preparing public examples. No private upstream security findings belong in this repository.

A passing supported run establishes only the configured fixed-handler boundary. It does not establish capability issuance or redemption, general native-code isolation, protection against a kernel exploit, or production readiness.
