# Hammerhead Core 0.2.0-core.1

A limited-scope native filesystem prerelease for macOS ARM64. The executable is `hammerhead-core`; this is a distinct Core product, not the original full Hammerhead v0.2 release.

## Included checks

| Rule | Scope |
|---|---|
| FILE-001 | Supported sensitive filename patterns |
| FILE-002 | Files above the configured size threshold (50 MiB default) |
| SEC-001 | Supported private-key headers and AWS-shaped IDs/assignments in eligible text files up to 5 MiB; redacted evidence |
| PROJ-001 | Recognized root README and license filename presence |
| PROJ-002 | Runtime/ecosystem manifest filename detection |
| GIT-001 | Supported textual patterns in the root `.gitignore` |

**GIT-002: NOT EVALUATED.** Advanced Git health analysis, branch/worktree status, tracking/history and native Git metadata collection are not included. The Git collector is absent from Core; no flag or fallback enables it. GIT-001 does not evaluate effective Git ignore behavior. Core does not claim full seven-rule coverage or complete repository security.

## Native acceptance and reporting

All **225 top-level Core tests passed**, including sockets, symlinks, root/path replacement, read/traversal/budget/cancellation failures, redaction, output errors and live Git/helper sentinels. Vet, offline module verification, a byte-identical native rebuild and clean-prefix installation/demo passed. The native-qualified environment is **Apple Silicon macOS 27.0.1 (26A434)** using Go 1.27.1. Older macOS versions, Intel macOS and Linux are unqualified and have no binary assets here.

Help, version and all reports identify Core and omitted GIT-002. JSON uses `hammerhead-core/v0.2`, explicit scope and granular coverage. Exit 0/1 requires completed Core work: 1 means a Security finding meets the selected threshold. Incomplete/failed/cancelled work, invalid input and output failures exit 2, including with `--fail-on none`. SIGINT/SIGTERM preserve cooperative cancellation and earlier findings.

## Explicit unsigned distribution

The macOS binary has the Go linker's **ad hoc signature only**, with **no Developer ID signature or Apple notarization**. Gatekeeper acceptance and downloaded/quarantined first launch are **unqualified**: the local assessment returned an internal Code Signing subsystem error. macOS or managed-device policy may block this download. Users requiring Apple-verified publisher identity or notarization should wait for an appropriately signed distribution. Checksums do not authenticate the publisher. No quarantine removal or Gatekeeper bypass is part of installation.

The only qualified OS version is macOS 27.0.1. The Mach-O minimum-load metadata of 13.0 is not an older-OS qualification or support claim.

## Assets and installation

- `hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz`
- `hammerhead-core_0.2.0-core.1_source.tar.gz`
- `hammerhead-core_0.2.0-core.1_docs.tar.gz`
- `SHA256SUMS`, `provenance.json`, `LICENSE`, `NOTICE`, `DEPENDENCIES.md`

Verify the archive with `SHA256SUMS`, read the included `INSTALL.md`, then extract into a new directory and use a writable installation prefix. Run `hammerhead-core version` to confirm the version and source base. If macOS blocks execution, stop; this release does not supply a bypass. Versioned Core documentation is included in the source and documentation archives.

Executable SHA-256: `e84f47227839157c34650d9ccc6f9aa54e70512f33bf96b0854be910f7c06905`.

The original full-Git release work and historical releases are preserved. A1-003 remains OPEN and original B4 remains BLOCKED for the full-Git release; this Core prerelease does not resolve or qualify that functionality.
