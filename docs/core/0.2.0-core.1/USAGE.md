# Usage and completion

```sh
hammerhead-core version
hammerhead-core --help
hammerhead-core audit /path/to/project
hammerhead-core audit /path/to/project --output json
hammerhead-core audit /path/to/project --quiet
hammerhead-core audit /path/to/project --fail-on none
hammerhead-core audit /path/to/project --exclude '*.generated' --max-file-size 10MB
```

| Exit | Meaning |
|---|---|
| 0 | Core completed under its reported policy; no Security finding meets the configured threshold, or the threshold is disabled |
| 1 | Core completed and a Security finding meets `--fail-on` (default high) |
| 2 | Partial, failed, cancelled, invalid request or output failure; also applies with `--fail-on none` |

Hygiene and Info findings never cause exit 1. Completed status means all six promised Core checks finished under eligibility/exclusions/limits, not complete repository security. Reports explicitly disclose omitted GIT-002. Missing required Core work does not become a clean scan.

Quiet stdout contains compact findings; quiet stderr contains Core scope, status, coverage and diagnostics. JSON stdout is one structured report; operational diagnostics remain separate on stderr. A failure before a scan result can be established emits a safe diagnostic and exit 2 rather than JSON. Writer/flush and broken-pipe failures also return 2.

SIGINT/SIGTERM request cooperative cancellation, preserve prior findings and return cancelled/2 when handled during scanning. Root authority, guarded reads and limits do not turn the scanner into an operating-system sandbox or an atomic filesystem snapshot. Reports include file/repository paths; handle them accordingly.
