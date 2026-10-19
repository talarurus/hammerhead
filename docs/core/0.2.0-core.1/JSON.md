# JSON contract: hammerhead-core/v0.2

`--output json` identifies `product: "Hammerhead Core"`, `version: "0.2.0-core.1"` and `schema: "hammerhead-core/v0.2"`. Scope includes exactly six rule IDs. GIT-002 appears in `scope.not_evaluated` with status `not_evaluated` and an exclusion reason, rather than in attempted-check coverage as passed.

Selected identity fields (an excerpt, not a complete report):

```json
{
  "product": "Hammerhead Core",
  "version": "0.2.0-core.1",
  "schema": "hammerhead-core/v0.2",
  "status": "completed",
  "scope": {
    "included_rules": ["FILE-001", "FILE-002", "GIT-001", "PROJ-001", "PROJ-002", "SEC-001"],
    "not_evaluated": [{"rule_id": "GIT-002", "status": "not_evaluated", "reason": "Git health and native Git metadata collection are excluded from Hammerhead Core"}]
  }
}
```

The full report additionally carries timestamp, repository root, threshold, summary, findings, coverage and diagnostics. Coverage records policy exclusions/effective limits, traversal completeness, per-check statuses/counters, reasons and truncation. Status is completed/partial/failed/cancelled. Included checks may be not_run when required work never started. Unknown telemetry never establishes completeness.

Security/Hygiene/Info are distinct. Only Security affects finding-threshold exit 1. Redacted evidence avoids full secret values; JSON preserves structured paths. Terminal formatting is sanitized separately. See the source archive's `testdata/contracts/v0.2` for illustrative full reports and the preserved native demo for actual output.
