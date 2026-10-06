# Hammerhead v0.2 Scan Result and Execution Contract

This document freezes the exact contracts that Phase 1 will implement so filesystem, engine, checks, CLI, and reporters all use the same definitions.

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
| completed | No                 | No           | 0         |
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

Diagnostics use typed structures, not free-form messages. They include `stage`, `code`, optional `rule_id`, optional `path`, and a `safe_message`. Raw Go error strings or Git stderr are strictly prohibited from being exported as JSON diagnostics. Bounded, finite reason codes map to user cancellation, invalid root, eligible read failure, budget exhaustion, Git timeout, etc.

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

**Incomplete / partial (forces partial status and exit 2):**
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

These values are proposed engineering policy limits bounding specific scanner-controlled work, retained data, output, and subprocess streams, pending the planned Phase 1 verification checkpoint.

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

## 8. Phase-1 Internal Data Direction

The following covers frozen internal direction for Phase 1 implementation (not code implemented by P0-03):
- `ScanResult` gains `Status`, `Coverage`, `Diagnostics` and separate threshold outcome.
- A dependency-leaf `internal/scanstate` package may hold shared bounded diagnostic/coverage state to avoid engine/fs/check import cycles.
- Counters are saturating and must never wrap.
- Future bounded finding production uses an `Emit(Finding)` error style sink.
- Guarded reads return typed outcomes distinguishing ordinary text/read success, binary/declared-size expected skips, safety rejection, and actual failure.
- Ordinary local-filesystem cancellation is cooperative between bounded chunks. Uninterruptible kernel/FUSE/network filesystem I/O remains a documented residual limitation.
