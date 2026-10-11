# Hammerhead v0.2 Scan Result and Execution Contract

This is the implemented development v0.2 Phase 1 contract. Foundation acceptance does not publish v0.2 or implement later phases. Historical v0.1 artifacts remain immutable.

## 1. Status Semantics

No zero/default status may imply success. The core scan `status` must be exactly one of:

- `completed`: All applicable required work completed within declared scope.
- `partial`: Valid scan scope established but one or more required operations, reads, checks, or result-production steps were incomplete.
- `failed`: Meaningful audit work could not begin due to setup/root/validation failure.
- `cancelled`: Cancellation or deadline interrupted an active audit.

Findings do not determine completion status.

### Cancellation Precedence

1. Cancellation interrupting an active run -> `cancelled`
2. Otherwise setup failure -> `failed`
3. Otherwise incomplete required work -> `partial`
4. Otherwise -> `completed`

## 2. Exit Semantics

The CLI exit code is determined by the combination of scan status and finding threshold:

| Status    | Threshold Exceeded | Fail-on None | Exit Code |
|-----------|--------------------|--------------|-----------|
| completed | No                 | Either       | 0         |
| completed | Yes                | No           | 1         |
| partial   | Any                | Any          | 2         |
| failed    | Any                | Any          | 2         |
| cancelled | Any                | Any          | 2         |

- `--fail-on none` disables finding-based exit 1.
- `--fail-on none` NEVER disables operational exit 2.
- Security findings alone affect threshold. Hygiene and Info findings do not.
- Invalid request -> exit 2.
- Report-write failure -> exit 2.

## 3. Coverage and Diagnostic Contract

Coverage metrics are operational telemetry and MUST NOT be called a percentage of repository security or safety. Coverage must distinguish:

- **policy**: lists applied `exclusions` and explicit `effective_limits`.
- **traversal**: `examined_entries`, `discovered_files`, `discovered_directories`, `inventory_complete`, `root_listing_complete`.
- **checks**: granular telemetry per check including `rule_id`, `check_ver`, `status`, `eligible_files`, `inspected_files`, `read_bytes`, and check-specific `reason_counts`.
- **reasons**: aggregate structured records of incomplete work across the scan, featuring `code`, `count`, `count_is_lower_bound`, and `examples`.
- **summary facts**: `findings_retained` (integer), `findings_truncated` (boolean, indicating if the cap was hit), `diagnostic_examples_omitted` (integer).

Diagnostics use typed structures, not free-form messages. They include `stage`, `code`, optional `rule_id`, optional `path`, and a `safe_message`. Raw Go error strings or Git stderr are strictly prohibited from being exported as JSON diagnostics. Bounded, finite reason codes map to `user_cancelled`, `deadline_exceeded`, `invalid_root`, `eligible_read_failure`, `budget_exhaustion`, `git_timeout`, `git_failure`, `git_unavailable`, `check_failure`, and `traversal_failure`.

Observed counts represent actual measurements, whereas zero values indicate explicitly no occurrences (or no inspection). Lower-bound flags mark counts that were stopped by a budget before complete enumeration. Check statuses include `completed`, `partial`, `failed`, `cancelled`, `not_applicable`, `unavailable`, and `not_run`.

## 4. Expected-Skip vs Incomplete Rules

**Expected/out-of-scope and not automatically operational failure (does NOT force partial status):**
- built-in exclusions
- user exclusions
- supported binary-content skip
- SEC-001 declared >5 MiB eligibility skip
- safety rejection of unsupported non-regular content
- broken/escaped/looping symlink safety rejection where defined by policy
- missing optional Git executable should be unavailable, not clean

**Incomplete required work (forces partial status and exit 2, or cancelled on cancellation):**
- depth/count/directory-width budgets exhausted
- aggregate byte/findings budget exhausted
- permission or I/O failure on eligible work
- file changed/vanished during eligible access
- check failure
- eligible root .gitignore cannot be read/parsed
- available Git operation unexpectedly fails/times out/overflows
- cancellation

Absence claims such as missing README/LICENSE/.gitignore require sufficient positive root-enumeration evidence. Unknown/incomplete inventory must not become "missing."

## 5. Resource Budgets

These frozen defaults bound specific scanner-controlled work, retained data, output and subprocess streams. They are applied in development v0.2 and recorded in policy; the CLI adds its configured five-minute cap, while an embedding caller may impose an earlier context deadline. Internal test overrides are reported rather than silently labeled as defaults.

They explicitly do NOT provide:
- a whole-process RSS cap
- an OS sandbox
- guaranteed interruption of uninterruptible kernel/FUSE/network-filesystem I/O

The budgets are:
- overall scan deadline: 5 minutes (300000 ms)
- depth: 50
- retained inventory: 100000
- directory batch: 256
- names per directory: 10000
- examined entries: 100000
- native per-read limit: 10 MiB (10485760 bytes)
- SEC-001 eligibility: 5 MiB (5242880 bytes)
- aggregate native read budget: 256 MiB (268435456 bytes)
- findings retained: 10000
- total diagnostic samples: 200
- examples per reason: 5
- diagnostic path: 16 KiB (16384 bytes)
- safe message: 2 KiB (2048 bytes)
- finding path: 16 KiB (16384 bytes)
- evidence: 2 KiB (2048 bytes)
- title/description/remediation: 8 KiB each (8192 bytes)
- Git per-command deadline: 10 seconds (10000 ms) within the overall deadline
- Git stdout: 4 MiB (4194304 bytes)
- Git stderr: 64 KiB (65536 bytes)
- Git termination grace: 1 sec (1000 ms)
- pipe/wait cleanup allowance: 1 sec (1000 ms)
- symlink resolution steps: 40

## 6. Determinism Guarantee

For unchanged input, policy, complete ordinary local-filesystem operations, and the same Git snapshot, all non-time report fields use canonical ordering.
We do NOT claim deterministic subsets after cancellation or time truncation.

## 7. Result and Error Policy

- An audit attempt can return a nonnil result alongside an error.
- Callers must preserve/render a meaningful nonnil partial result. Setup failures may exit 2 without a complete scan report, while meaningful partial results must be retained and rendered.
- Setup/cancellation causes may still return errors.
- Typed diagnostics/status represent ordinary incomplete work.
- A report-write failure is an invocation failure, not a rewrite of scan completeness.

## 8. Implementation and residual boundaries

`ScanResult` carries Status/Coverage/Diagnostics and observed threshold state. The dependency-leaf `internal/scanstate` holds shared types and the bounded `Emit(Finding) error` collector. Checks stop emission/match production on budget errors; native reads return typed text/binary/too-large/safety/error/budget outcomes. Traversal uses pinned directory descriptors; reader probing/content share one verified handle. Relative file links within the root are supported with exclusions on their targets; absolute and directory links are rejected.

Policy exclusions are a sorted unique set of built-in names, additional directory names and user patterns, not a count of excluded descendants. Examined entries include observed excluded/special entries; retained inventory includes the root directory. A directory exceeding width is not traversed from a nondeterministic prefix. Known unstarted work is zero with `not_run` and incomplete inventory flags; it does not assert absence in the target. Unknown values in manually constructed/embedded results must not be converted to fake success or measurements by a reporter.

Git is an explicit external-metadata exception: worktrees may reference metadata outside the native root. Missing executable is `unavailable`; ordinary non-Git/audited-subdirectory health is `not_applicable`; unexpected failures/timeouts/output overflow are partial. No check executes Git or reads raw HEAD; raw stderr is not exported. `GIT_OPTIONAL_LOCKS=0` suppresses optional index writes.

Ordinary local-filesystem cancellation is cooperative between traversal batches, reads, checks and match/emission work. Uninterruptible kernel/FUSE/network filesystem I/O, hard links and mounts are residual limits, not an OS sandbox or absolute deadline guarantee. Logical budgets are not an RSS cap. Special-file subprocess tests use outer watchdogs; no privileged device nodes are created. See [OUTPUT.md](OUTPUT.md) for checked writes, quiet/JSON streams, bounded terminal diagnostics and the executable’s Unix SIGPIPE policy, and [CONTRIBUTING.md](../../CONTRIBUTING.md) for native versus compile-only platform evidence.
