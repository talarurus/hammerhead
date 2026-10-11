# JSON Schema v0.2 Migration Decision

The repository audit found no independent IN-REPOSITORY or CI consumer requiring a legacy serializer, but external consumers may exist.

Therefore:
- The active development schema is `hammerhead/v0.2`.
- We will NOT implement `--schema hammerhead/v0.1`.
- We will NOT implement a v0.1 compatibility serializer.
- We preserve immutable v0.1 fixtures and the `v0.1.0` release.
- The intentional schema and exit behavior break is documented in `MIGRATING-TO-V0.2.md`.
- New behavior will NOT be mislabeled as v0.1.

## Implemented schema structure

The `hammerhead/v0.2` schema represents the unified result contract described in `SCAN-RESULT.md`.

It includes the following fields and structures:
- `schema` (string): Always "hammerhead/v0.2".
- `status` (string): Execution outcome (`completed`, `partial`, `failed`, `cancelled`).
- `threshold` (object): Threshold policy.
  - `fail_on` (string): e.g., "high", "critical", "none".
  - `exceeded` (boolean): True if observed security finding severity meets/exceeds `fail_on`. Must be false if `fail_on` is "none".
- `repository` (object): Scan target path.
  - `root` (string): Absolute or relative root path.
- `version` (string): Application build version.
- `timestamp` (string): Execution time in RFC3339.
- `summary` (object): Numeric facts preserving familiar v0.1 semantics.
  - `findings_count` (integer): Total retained/report findings count, not an uncapped detection total.
  - `class_counts` (object): Map of finding class (`security`, `hygiene`, `info`) to its count.
  - `highest_security_severity` (string): Highest observed severity among Security findings (e.g., "critical", "high"), including a finding rejected by the production cap. Empty if none.
  - `checks_attempted` (integer): Number of checks attempted (not necessarily completed).
- `findings` (array of objects): Array of findings.
  - `rule_id` (string): e.g. SEC-001.
  - `class` (string): `security`, `hygiene`, or `info`.
  - `severity` (string): e.g. critical, high, medium, low, info.
  - `title` (string): Short descriptive title.
  - `description` (string): Details.
  - `path` (string): Affected file.
  - `evidence` (string): Redacted evidence string (no raw confirmed secrets).
- `coverage` (object): Detailed run completion facts.
  > Production engine results report actual observed counters, effective limits,
  > exclusions and explicit check states, including measured zero work before any
  > stage starts. Those zeros never establish absence in an incomplete inventory.
  > Reporters preserve `null` if an embedding caller supplies genuinely unknown
  > telemetry; they do not invent measurements. The older synthetic serializer
  > fixtures intentionally exercise this representation separately from final
  > engine instrumentation.
  - `policy` (object): `exclusions` (array of strings), `effective_limits` (object mapping string to integers with canonical unit-bearing keys including max_depth, max_retained_inventory_entries, etc.).
  - `traversal` (object): Contains non-negative integers `examined_entries`, `discovered_files`, `discovered_directories`, and booleans `inventory_complete`, `root_listing_complete`.
  - `reasons` (array of objects): Aggregate structured records of incomplete work across the entire scan. Fields: `code` (string), `count` (integer), `count_is_lower_bound` (boolean), `examples` (array of strings).
  - `checks` (array of objects):
    - `rule_id` (string), `check_ver` (string)
    - `status` (string): `completed`, `partial`, `failed`, `cancelled`, `not_applicable`, `unavailable`, `not_run`.
    - `eligible_files` (integer), `inspected_files` (integer), `read_bytes` (integer)
    - `reason_counts` (array of objects): Check-specific accounting. `code` (string), `count` (integer), `count_is_lower_bound` (boolean), `examples` (array of strings).
  - `findings_retained` (integer)
  - `findings_truncated` (boolean): True if the finding production cap was hit, making exact total unknown.
  - `diagnostic_examples_omitted` (integer)
- `diagnostics` (array of objects): List of partial/failure conditions.
  - `stage` (string): e.g. "traversal", "check", "git".
  - `code` (string): Bounded finite reason code (e.g. "budget_exhaustion", "git_timeout").
  - `rule_id` (string, optional).
  - `path` (string, optional).
  - `safe_message` (string): Safe typed error/telemetry message; never raw Git stderr or arbitrary service errors.

## Presentation, version and compatibility

The default development version is `0.2.0-dev`; build metadata may override it. `timestamp` is RFC3339 and is normalized only in tests. Original paths/IDs and JSON string contents are unaffected by terminal sanitization. stdout is one document whenever output succeeds; operational messages use stderr. Setup/write failure may leave no complete document and still exits 2. See [OUTPUT.md](OUTPUT.md) and [migration notes](../MIGRATING-TO-V0.2.md).

The frozen examples in `testdata/contracts/v0.2` are synthetic design examples, not exact captures of every production policy or current version default. See their [provenance and normalization guide](../../testdata/contracts/README.md). The historical v0.1.0 tag/fixtures retain their original schema and module identity.
