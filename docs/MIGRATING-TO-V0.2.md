# Migrating to development Hammerhead v0.2

`v0.2-dev` implements the Phase 1 trustworthy core and defaults to `0.2.0-dev`. This is an intentional schema/exit/link/budget change, not a published v0.2 release or completion of later phases. No legacy serializer or `--schema hammerhead/v0.1` option is provided: no independent in-repository/CI consumer required one, though external consumers may exist.

## Reports and exits

Active JSON is `hammerhead/v0.2`: `status`, `threshold`, `repository`, `version`, `timestamp`, `summary`, `findings`, `coverage` and typed `diagnostics`. Finding identity and familiar finding fields remain unchanged. `summary.findings_count` is retained findings; `highest_security_severity` is highest observed Security severity, even if a cap rejected that record. `checks_attempted` is attempted work, not completed work. See [JSON-V0.2.md](contracts/JSON-V0.2.md).

| Status | Threshold outcome | Exit |
| --- | --- | --- |
| `completed` | No Security hit, including `none` | 0 |
| `completed` | Security threshold reached | 1 |
| `partial`, `failed`, `cancelled` | Either, including `none` | 2 |
| Invalid request/status or output failure | Irrelevant | 2 |

In v0.1.0 a check error could coexist with exit 0; development v0.2 makes incomplete required work operational failure. A nonnil partial/cancelled result is rendered even when an error accompanies it. Setup failure can produce no report, and failed writes cannot promise complete JSON. Preserve the Hammerhead exit status after parsing; [README](../README.md) writes the report outside the audited target and returns the saved status.

Terminal reports show status/coverage with zero findings. Quiet stdout retains compact findings, with operational summaries/diagnostics on stderr. JSON stdout has one document when writing succeeds; no banners/progress/raw CLI errors share it. Terminal ANSI/OSC/control/bidi sanitization and bounds never mutate JSON paths, stored IDs or matching; sanitization is separate from secret redaction. Short/error/flush writes override finding outcomes with exit 2. The Unix executable ignores SIGPIPE; embedders must provide equivalent signal policy for real standard descriptors. See [OUTPUT.md](contracts/OUTPUT.md).

## Native scope, links and budgets

Native checks use the guarded rooted reader, including binary probing from the same verified regular-file handle. Relative in-root file symlinks are supported with resolved-target exclusions; absolute links, directory links and unsupported special files are safety rejections. This can reduce coverage compared with permissive old link behavior. Root aliases selected by the user are resolved before pinning. Hard links/mount crossings and uninterruptible filesystem I/O are residual limits, not promises of an OS sandbox or absolute cancellation.

Expected exclusions, binary content and SEC-001 files over 5 MiB need not cause exit 2. Eligible read/parse failures and depth/count/width/read/findings-budget exhaustion do. Missing README/LICENSE/.gitignore requires complete relevant root enumeration and no excluded/unreadable recognized candidate. Unknown is not absence.

Traversal/read/emission/match production stop at their respective caps; diagnostics may omit samples while preserving aggregate accounting. Policy lists the applied limits and exclusions. `--max-file-size` changes FILE-002’s threshold only, separate from 10 MiB guarded reads, SEC-001’s 5 MiB eligibility and the 256 MiB aggregate budget. [SCAN-RESULT.md](contracts/SCAN-RESULT.md) records all frozen budgets. They do not imply a whole-process memory cap.

## Git context in v0.2-dev

C11 removes the raw `.git/HEAD` fallback. When Git is missing, native checks
continue, GIT-002 coverage is `unavailable`, and a bounded `git_unavailable`
diagnostic explains that Git health was not evaluated. This alone does not
make the audit partial. Ordinary non-Git directories and audited Git
subdirectories have `not_applicable` Git health coverage. Available Git
operations that time out, exceed output limits, return malformed output, or
fail unexpectedly make the audit `partial` (exit 2, including `--fail-on none`).

The engine collects detection, branch, and root-only worktree status once;
GIT-002 consumes that snapshot without filesystem or subprocess access. Normal,
unborn, and detached branch states are distinguished without reading HEAD.
Porcelain v1 NUL records count each rename/copy once and preserve filenames with
newlines or control characters; old line-based counts could overcount them.
Submodule status remains ignored, and `GIT_OPTIONAL_LOCKS=0` suppresses optional
index refresh writes.

Git worktrees may reference metadata outside the audited directory. That is an
explicit exception for the existing bounded Git executable, separate from the
rooted native-content boundary. It does not give checks access to those files.

An exact C-locale non-repository diagnostic is accepted only when a bounded
metadata existence probe finds no `.git` marker in the target or its ancestors.
A marker, an inaccessible probe, or exceeding 256 ancestor steps leaves Git
state ambiguous and makes the audit partial. The probe uses only `Lstat`; it
reads no Git file content and never supplies root, branch, or status data.

## Preserving historical installations

The annotated `v0.1.0` tag and its original release commit, published metadata, original download assets and historical fixtures remain unchanged. Its Go module is `github.com/ammaarrehman/hammerhead`; it cannot automatically be installed under `github.com/talarurus/hammerhead`. Existing release assets remain at the original repository until a separate migration. Development clones/imports use [talarurus/hammerhead](https://github.com/talarurus/hammerhead), branch `v0.2-dev`.

Pin the historical release if private consumers require `hammerhead/v0.1`, then migrate status/coverage/threshold handling explicitly. Do not treat a successful threshold result as perfect detection or credential validation. The [contract fixture guide](../testdata/contracts/README.md) distinguishes historical captures, design examples and active serializer goldens. The frozen roadmap remains unchanged; its older “confirmed pair” or unrestricted safety wording does not describe current detector guarantees.
