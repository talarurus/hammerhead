# Core rule inventory

| Rule | Promised observation | Class |
|---|---|---|
| FILE-001 | Supported sensitive filenames; no content or credential validity inference | Security |
| FILE-002 | Files strictly over 50 MiB by default; configurable with `--max-file-size` | Hygiene |
| SEC-001 | Supported private-key headers and AWS-shaped IDs/secret assignments in eligible text up to 5 MiB; evidence redacted; no credential validation | Security |
| PROJ-001 | Recognized root README/license filename presence; no content or license suitability evaluation | Hygiene |
| PROJ-002 | Runtime/ecosystem manifest filenames; no interpreter/package-manager execution | Info |
| GIT-001 | Supported textual patterns in root `.gitignore`; no effective ignore/negation/tracking/nested/global ignore evaluation | Hygiene |

**GIT-002: NOT EVALUATED.** Its implementation and native Git collector are absent. It is not a seventh completed or passed Core check. No flag or fallback enables it.

SEC-001 matches supported private-key headers and AWS-shaped identifiers, with supported same-file secret assignments affecting severity. It is a narrow pattern scanner, not an entropy scanner or credential validator. Pattern matches cannot establish pairing, activity, exposure or compromise. FILE-001 exemptions, thresholds and priority remain those of the reviewed native implementation.

`.git` entries and common dependency/build/cache directories are excluded. Reported exclusions and eligibility define scope. Out-of-root symlinks and special files are safety skips; in-root eligible aliases may be read. Binary and oversize content is outside secret inspection. Default bounds include depth 50, 100,000 examined entries, 10 MiB native reads, 256 MiB aggregate reads, 10,000 retained findings and a cooperative five-minute deadline. `--max-file-size` changes FILE-002 only.

Eligible read/path mutation, required traversal/read/parse failure, exhausted budgets and cancellation produce incomplete status and exit 2; expected policy exclusions do not imply that omitted data was inspected.
