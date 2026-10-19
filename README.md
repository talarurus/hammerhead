# Hammerhead Core 0.2.0-core.1

A limited-scope prerelease candidate for six native filesystem checks. The executable is `hammerhead-core`. **GIT-002 is NOT EVALUATED.** Git health, Git metadata collection, history, tracking, branch/worktree status and repository helpers are omitted. Core makes no claim of full seven-rule coverage or complete repository security.

Native Core acceptance passed all 225 top-level tests on **Apple Silicon macOS 27.0.1 (26A434)**. The executable has an ad hoc signature only: **no Developer ID signature or Apple notarization**. Gatekeeper acceptance is unqualified; downloaded software may be blocked. No earlier minimum macOS version, Intel macOS or Linux binary is qualified. This package is **READY FOR EXPLICIT UNSIGNED PRERELEASE APPROVAL** and awaits founder approval before publication. See [release results](release/RESULTS.md) and [distribution review](release/DISTRIBUTION-REVIEW.md).

| Included rule | Promised behavior |
|---|---|
| FILE-001 | Supported sensitive filename patterns; contents and credential validity are not inferred |
| FILE-002 | Files strictly above 50 MiB by default; `--max-file-size` changes this size observation only |
| SEC-001 | Supported private-key headers and AWS-shaped IDs/secret assignments in eligible text files up to 5 MiB; evidence is redacted; credentials are not validated |
| PROJ-001 | Recognized root README and license filename presence; no content or license adequacy evaluation |
| PROJ-002 | Runtime/ecosystem manifest filenames; no interpreter, build tool or package manager execution |
| GIT-001 | Supported textual patterns in root `.gitignore`; no effective ignore, negation, tracking or nested/global ignore evaluation |

## Local installation and usage

The macOS archive is `hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz`. Follow [INSTALL.md](INSTALL.md) to verify the published archive, extract into a new directory and preserve platform protections. From this source workspace, verify all prepared public assets with `(cd dist && shasum -a 256 -c SHA256SUMS)`.

```sh
hammerhead-core version
hammerhead-core audit /path/to/project
hammerhead-core audit /path/to/project --output json
hammerhead-core audit /path/to/project --quiet
```

Choose an existing writable bin directory for `/your/chosen/bin`. Installation does not replace the full `hammerhead` executable. There is no full-Git mode, build tag, hidden switch or runtime fallback. `version`, root help and audit help identify Core; all reports explicitly identify omitted GIT-002. JSON uses the distinct `hammerhead-core/v0.2` schema with `product`, `scope.included_rules` and `scope.not_evaluated`.

Exit 0 means the promised Core work completed without a Security finding at the selected threshold; exit 1 means completed Core work with a Security finding meeting `--fail-on` (default `high`). Hygiene and informational findings never cause exit 1. Partial, failed, cancelled, invalid input and output failures exit 2, even with `--fail-on none`. Quiet mode sends findings to stdout and Core scope/status/coverage to stderr. A setup failure before a scan result exists emits a safe diagnostic and exit 2 rather than a JSON report.

`completed` refers to Core's declared filesystem policy, eligible content and explicit exclusions. It does not establish security of omitted files or Git history. The report records effective limits and exclusions. `.git` entries are always skipped; common dependency/build/cache directories are excluded. External symlinks, special files, binary content and content above the rule's size limit are policy skips. Read or traversal failures affecting required work, detected eligible-path mutation, cancellation and exhausted budgets produce incomplete status. Reports include repository and file paths; handle reports accordingly.

## Build, test and bounded demo

Use Go 1.27.1 to reproduce the tested toolchain (module minimum 1.26.0). Existing dependency versions and `go.sum` are retained. No extra scanning engine is included.

```sh
make build
make check
python3 release/smoke.py dist/hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz
```

`make check` runs `go vet` and the full Core suite with the race detector, including the required socket tests. The demo installs the packaged executable into a disposable prefix and scans only bounded synthetic fixtures. It checks all included rules, clean/threshold/incomplete exits, report scope, redaction and a live Git/helper sentinel. It does not scan this checkout or any real repository.

Native acceptance evidence is complete in `release/evidence/native-acceptance/`; no further full-suite rerun is needed for the documentation/package refresh. `release/qualify-macos.sh` is retained as the reproducible acceptance recipe. Versioned public documentation is in [docs/core/0.2.0-core.1](docs/core/0.2.0-core.1/README.md). See [acceptance matrix](release/ACCEPTANCE.md), [security review](SECURITY.md), [release notes](RELEASE-NOTES.md), [dependency inventory](DEPENDENCIES.md) and [provenance](dist/provenance.json).
