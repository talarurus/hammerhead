# v0.1 Historical Contract

This directory contains captured output and behavior from Hammerhead v0.1.0 before implementing v0.2 changes.

**Source Revision**: `92843f3c2d9b365dcd6e502fd7bfbe2ac74229fa` (v0.1.0 tag)

## Normalization
To ensure reproducibility:
- `timestamp`: Normalized to `2026-10-05T00:00:00Z` in JSON output.
- `repository.root`: Normalized to `/tmp/hammerhead-test-root`.
- `version`: Normalized to `0.1.0`.

To preserve the *exact* bytes outputted by the `v0.1` formatters—including deterministic trailing whitespace and newlines—without causing `git diff --check` failures, the terminal and quiet outputs are encoded as escaped JSON strings in `terminal_fixtures.json` and `quiet_fixtures.json`. No trimming or string normalization is applied to the formatter output.

## Exit Semantics (Observed in v0.1)
- **Empty Result**: Exit 0
- **Mixed Security / Hygiene / Info**: Exit 1 (due to high/critical security finding)
- **Hygiene-only Result**: Exit 0
- **Check-error Result**: Exit 1 (if contains security finding), but errors themselves didn't force a specific non-zero exit in `Engine.ScanResult.ExitCode(failOn)`.
- **Zero-findings + Error**: Exit 0 (known defect)
- **Skipped-entry**: Skipped items didn't alter exit code and were absent in JSON output (known defect).

These behaviors are captured intentionally as they existed in v0.1.0. Do not modify these fixtures.
