# Core acceptance matrix — 0.2.0-core.1 final review

Reviewed against the fixed six-rule registry, default application path, all local production imports and variants, actual executable behavior and linked dependency/symbol evidence. Only disposable synthetic fixtures are used. Qualification requires every required row, including sockets, to pass on the target native platform. A build or selected subset is insufficient.

| Requirement | Acceptance / negative controls | Native result |
|---|---|---|
| Six included rules | `TestCore_RuleAcceptance`: clean baseline completes all six with zero findings; separate executable fixtures produce exactly the expected FILE-001/002, SEC-001, PROJ-001/002 and GIT-001 finding and truthful exit. Existing per-rule variant, boundary and exemption tests remain. | Passed |
| Core identity / omissions | `TestCore_GitAndHelperIsolation`, `assertCoreContract`: distinct help/version/schema/product/scope; six completed check records; GIT-002 explicitly not evaluated, absent from attempted checks and findings; no Git budgets. Quiet scope goes to stderr. Unknown Git switches exit 2. | Passed |
| Git and helper isolation | Live fake `git`, credential, shell and helper sentinels; direct invocation produces the marker (positive control), Core leaves it absent. Synthetic `.git` directory, gitfile, symlink, nested metadata and no-metadata roots; hostile Git config/environment/helper settings; all three reporters. | Passed |
| Structural isolation | `TestCore_NoProcessOrGitImplementation` inspects every local production variant. Production `go list -deps` contains neither `os/exec` nor the full-Git package; linked symbols contain no collector, Git-health or pathname-observer entrypoints. | Passed |
| Native filesystem regression | All 15 production filesystem files match protected SHA-256. Applicable original fs/reader/resolver/walker, check, collector, engine, application, CLI and reporter tests run in the full Core suite. | Passed |
| Root authority / symlinks | `TestCore_RootAuthorityThroughAllChecks`: unchanged root vs rename, replacement directory and external replacement symlink after traversal. Findings remain from the pinned original root. Existing `TestA2R1_RootAuthority`, `TestReader_Symlinks`, walker and reader ancestor/symlink swap tests supply benign in-root controls and rejected escape controls. | Passed |
| Required path/read failures | `TestA2R2_RequiredReadFailures`, `TestA2R2_EligibleMutationCLI`, native reader mutation and same-type/ancestor replacements; unchanged, relative alias, excluded, binary and oversize controls. Required missing/changed reads are partial/2 and retain earlier findings; policy skips do not fabricate failures. | Passed |
| FIFO and special types | `TestReader_FIFORejectedWithoutWriter`, replacement-with-FIFO tests and walker nonregular-presence tests verify zero content/no hang. | Passed, including sockets |
| Socket and combined FIFO/socket executable | `TestReader_SocketRejected` and `TestCLI_SpecialFileNoHang`, with owned listening Unix socket, no FIFO writer and subprocess watchdog. These are required and remain in the suite. | **Passed in supplied native acceptance**; earlier sandbox failures retained as history |
| Traversal, read, output budgets | `TestWalk_*Bounded`, root enumeration/depth/batch cancellation, `TestAcceptance_ProductionStopsAtCaps`, finding/aggregate-read/diagnostic limit integration tests. Root setup/read/check failures and exact/ineligible boundaries have controls. | Passed |
| Cancellation / deadline | `TestCLI_CancelDuringScan`, `TestA2R1_EngineLifecycle`, engine/check cancellation, reader cancellation, cancelled-last-check and unstarted coverage tests: cancelled/failed result, prior findings preserved, zero unstarted work, exit 2 even with threshold disabled. | Passed, including actual SIGINT/SIGTERM command wiring with test-only scheduling/observation overlays (`TestCore_CommandSignalCancellation`) |
| Redaction and hostile report data | `TestCore_RedactionAcrossReporters`, existing secret tests and sanitizer/terminal-injection/malicious-path tests; real stdout/stderr separation, safe error text and broken-pipe/write/flush failures. | Passed |
| Completion and exits | Actual executable clean=0, Security threshold=1, hygiene/info=0; `none` disables only finding threshold. Incomplete reads/traversal/budgets/checks/cancellation/output errors=2. Existing application, engine and CLI exit tests; active Core serializer goldens and independent illustrative contract validation. | Passed |
| Full Core regression / race | `go test -race -json -count=1 ./...`, no test exclusion/skip filter. | **Passed: 225 top-level tests, zero failures/test skips, no race detector report** |
| Static analysis | `go vet ./...`; formatting; pinned module cache verification. | Passed |
| Native artifact / install | Actual Mach-O ARM64 build; clean disposable-prefix install from package; bounded synthetic demo with scope, detections, redaction, exit 0/1/2 and sentinel checks; reproducible rebuild/hash comparison. | See `RESULTS.md` for executed results |
| Distribution qualification | Signing/notarization, Gatekeeper with quarantine, supported minimum macOS and final review. | Explicit unsigned option; no Developer ID/notarization or Gatekeeper pass; only macOS 27.0.1 qualified; founder approval pending |

## Excluded full-product tests

These are not in Core's suite and **are not counted as passing Core tests**. Original sources, tests and evidence remain unchanged in the protected full Hammerhead checkout.

- All `internal/git` implementation/tests and `internal/check/git_health_test.go`.
- `internal/engine/git_snapshot_test.go`; `TestA2R1_GitBindingSetupFailure` from root lifecycle tests.
- `internal/cli/root_handoff_test.go` (the full-Git pathname/helper handoff) and `internal/cli/metadata_refusal_test.go`.
- `TestCLI_GitTimeoutRetainsNativeFindings` and its synthetic Git process helper from CLI integration tests.
- `TestA2R1_GitNamespaceGuard`, `TestA2R1_NamespaceFailureCleanup` and `TestA2R1_NamespaceSetupExhaustionCleanup`: unused Git pathname-observer support, not native Core traversal/reader behavior.
- The two GIT-002 variants, Git-repository helper and seventh-rule inventory/cancellation expectations in mixed native-check test files. Native variants and all six cancellation tests remain.
- Historical full-product v0.1 reporter fixture-shape/known-defect tests and fixtures. Current reporter safety/exit/serialization tests and Core goldens remain.

The supplied native handoff `/tmp/hammerhead-core-native.yiNhrz` passed the whole applicable Core suite, including sockets, without filters. Evidence was independently verified and copied to `release/evidence/native-acceptance/`. No unnecessary security rerun is required for unchanged tested inputs. This does not publish, waive original full-Git issues or approve unsigned distribution.
