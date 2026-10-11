# Hammerhead architecture

This describes development `0.2.0-dev`, module `github.com/talarurus/hammerhead`. The immutable v0.1.0 release and its output fixtures describe historical behavior. Foundation completion is not a v0.2 release or authorization for later phases.

## Execution layers

1. `cmd/hammerhead` establishes the Unix SIGPIPE policy and calls `cli.Run`.
2. `internal/cli` validates format, threshold, size, globs and argument count before invoking the audit service, injects stdout/stderr, applies the five-minute context cap, renders nonnil results even when an error accompanies them, and returns operational exit 2 for output failure.
3. `internal/app` validates typed requests, copies caller-owned slices, assembles a fresh registry/options and centralizes exit resolution. Completed + Security threshold hit returns 1; completed without a hit returns 0; partial/failed/cancelled/invalid status returns 2. `none` never suppresses 2.
4. `internal/engine` establishes native scope, walks once, collects one Git snapshot, runs checks in explicit registry order, collects bounded emissions, finalizes coverage and sorts reports. `internal/engine/registry.go::DefaultRegistry` assembles all seven checks without `init()` registration; duplicate IDs return registration errors.
5. `internal/fs` bounds traversal and provides the guarded content reader. Checks consume the supplied inventory and `sc.ReadFile`; none opens native content itself.
6. `internal/check` implements `Meta() Meta` and `Run(context.Context, *ScanContext) error`. Findings flow through `sc.Emit(Finding) error`; checks stop on budget errors and cooperate with cancellation. `CheckOptions` carries per-run thresholds without mutating check objects.
7. `internal/scanstate` holds completion/coverage/diagnostic types and the bounded collector. `internal/finding` is serializable data and ordering/identity logic.
8. `internal/reporter` renders terminal/quiet/JSON through checked writers. Stored observations are unchanged by terminal sanitization.

## Native filesystem boundary

The Unix implementation pins directory descriptors and resolves and opens components relative to them, checking type and identity before reading. It uses nonblocking, no-follow opens and fstat verification of the actual handle; binary classification and full read share that handle. The reader and traversal are separate stages: traversal metadata does not authorize a later unchecked path open. The old v0.1 binary-probe/raw-open architecture does not describe development v0.2.

Relative in-root regular-file links are supported with a 40-step bound and resolved-target exclusions. Directory symlinks and absolute links are rejected. Leaf/ancestor swaps, changed identity, special files and aliases into excluded content do not regain plain absolute-path access. README/LICENSE/.gitignore absence requires complete relevant root enumeration with no excluded/unreadable recognized candidate; unknown presence does not emit “missing.”

The selected root alias is resolved before pinning. This is not an OS sandbox or a prohibition on mount crossings/hard links. Ordinary-user local filesystem execution is the supported boundary; arbitrary uninterruptible kernel/FUSE/network filesystem calls can outlast cooperative context cancellation. No abandoned goroutine per file or native scanner subprocess isolation is claimed.

## Work budgets and completion

[SCAN-RESULT.md](docs/contracts/SCAN-RESULT.md) records the complete frozen limits. Traversal uses depth 50; 100,000 retained and examined entries; 256-entry batches; 10,000 names per directory. An exceeded directory is not traversed from an arbitrary prefix. Reads are bounded separately: 10 MiB native maximum, 5 MiB SEC-001 eligibility, 256 MiB aggregate actual bytes. `--max-file-size` changes FILE-002’s observation threshold only.

At 10,000 retained findings the next attempted emission stops production, marks partial and records lower-bound observation state. Payloads, 200 diagnostic samples and five examples per reason are bounded before retention. Omitted diagnostic samples do not themselves imply incomplete work; aggregate accounting continues. These controls bound scanner-controlled work and data, not whole-process RSS or every filesystem operation.

Completed means all applicable required work finished within policy. Expected exclusions, binary/SEC-001 size skips and unsupported-entry safety rejections need not make it partial. Eligible read/parse errors and traversal/production budgets do. Cancellation retains findings already emitted. Status/coverage remain visible with no findings. Unstarted checks have measured zero work and `not_run`; that never establishes absence in an unexamined tree.

## Git metadata exception

Only the installed Git executable is invoked, with separate arguments and no shell. Executables in or aliased through the target are rejected. Environment/config restrictions disable hooks, fsmonitor, optional index writes, prompting and global/system config. Each command has a 10-second deadline, stdout 4 MiB and stderr 64 KiB; overflow cancels production. Owned process groups receive TERM, up to one second grace, then KILL, with one second additional cleanup allowance. Descendant pipe/process tests use readiness barriers and parent watchdogs.

Git owns branch/worktree metadata, which may live outside the audited root for worktrees. The native reader never gains that authority. Missing Git is `unavailable`, ordinary non-Git/subdirectory health is `not_applicable`, and available failures are partial. A bounded metadata-existence probe disambiguates non-repository failures; it does not read HEAD or fabricate state. GIT-002 consumes the engine snapshot, never executes Git itself. Raw Git stderr is neither a finding nor a diagnostic.

## Findings and output

Security/Hygiene/Info remain separate; only Security participates in exit 1. All seven rules and 35 documented observation variants retain detection, priority, thresholds, severity, confidence and ID inputs. A header/filename/AWS-shaped co-occurrence is not credential validation, pairing, exposure or commitment. Short hash IDs can collide; findings are not deduplicated by ID.

Complete scans on unchanged roots/policy/Git snapshots order every non-time finding/diagnostic/check field canonically. Cancelled or time-truncated subsets need not be identical. JSON uses `hammerhead/v0.2`; no compatibility serializer is provided. Secret redaction is enforced by producers. Terminal sanitization separately strips controls/OSC/bidi, bounds text and prevents line spoofing; it is not path privacy or secret redaction.

Normal terminal reports show status/coverage; quiet sends compact findings to stdout and operational summaries to stderr. JSON stdout is a single document on successful output. Short/error/flush writes stop that stream and cause exit 2; safe stderr is best effort. The executable ignores Unix SIGPIPE so real fd 1/2 EPIPE returns through checked writers. Embedders must supply equivalent signal policy if they need that guarantee. See [OUTPUT.md](docs/contracts/OUTPUT.md).

## Scope and validation

Native macOS/Linux tests, race tests, malicious synthetic fixtures, process watchdogs, deterministic producer counters and four CGO-disabled compile targets are distinct evidence. [CONTRIBUTING.md](CONTRIBUTING.md) states which architectures actually run. External scanners, configuration, explanation catalogs/renderers, GUI, plugins and integrations remain future work; no extension framework is implemented here. The frozen roadmap remains unchanged; its historical examples are qualified by the current [claims ledger](docs/contracts/CLAIMS.md).
