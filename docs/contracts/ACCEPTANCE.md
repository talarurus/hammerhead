# Phase 1 acceptance evidence (C15 / G12)

This index maps the frozen plan's 19 acceptance criteria to tests/source review for the C15 review candidate. It is not a release announcement or proof that later phases are implemented. The validation export records exact commands, toolchains, native architectures, failures/retries and results; remote GitHub Actions still requires a later authorized push/PR.

| Frozen gate | Evidence / regression control |
| --- | --- |
| 1. Immutable baseline | Tag object/release commit pins in contract fixture README; historical manifest tests; final byte/tag/scope comparison in validation |
| 2. Full exit matrix | `TestScanResult_ExitPrecedence`, `TestCLI_InvalidResultEnums`, schema negative/exit contract tests; completed/partial/failed/cancelled with threshold/default/none |
| 3. No misleading clean result | `TestCLI_PartialScanEndToEnd` combines a real eligible vanished-file read failure with retained native findings/none and zero findings in all formats; G11 status/coverage/stream tests |
| 4. Guarded content only | `TestReader_SameHandleProbeAndRead`, reader swap/alias tests; static content-open review; checks use supplied ReadFile |
| 5. Special files | `TestCLI_SpecialFileNoHang` watches actual FIFO/socket traversal and direct guarded reads; `TestReader_ReplacementWithFIFO`, FIFO/socket reader child watchdogs; synthetic device metadata rejection; zero content bytes |
| 6. Containment | Reader leaf/ancestor swaps, aliases into excluded directories, relative-link compatibility and absolute-link rejection; walker adversarial directory replacement tests |
| 7. Bounded work | `TestAcceptance_ProductionStopsAtCaps` counts actual filename/match emissions and read calls; `TestWalk_LimitsStopEnumeration` counts batches and asserts no retained child prefix; collector/read budgets/payload limits; policy telemetry tests |
| 8. Cancellation | `TestCLI_CancelDuringScan` synchronizes on actual check entry after findings were emitted, then demands completion within 2 s; pre-cancel, traversal-batch and reader-chunk regressions |
| 9. Git lifetime/output | `TestCLI_GitTimeoutRetainsNativeFindings` uses actual command timeout/failure through the real CLI/runner with native findings retained; G7 independent stream caps, process groups, pipe timeout, cancellation and forced cleanup |
| 10. Stateless requests | App/engine/CLI sequential and concurrent option tests and race suite; shared caller backing-array tests |
| 11. Early validation | `TestCLI_InvalidOptionsDoNotScan`, typed request validation, byte-size boundary and `FuzzParseByteSize`; no scan/Git/content call on invalid flags |
| 12. Coverage/absence | G5/G6 inventory unknown/exclusion/read/parse tests; `TestAcceptance_EffectivePolicyTelemetry` and unstarted measured-zero accounting |
| 13. Output failures | G11 every-write-position, short/error/flush, failing stderr, help/version, single-document JSON and real broken-pipe subprocess tests |
| 14. Determinism | G9 repeated/shuffled report/traversal/diagnostic/manifest tests; unchanged ID formula, no dedup by ID |
| 15. Detection integrity | All seven checks, rule inventory/variants, positive/negative/redaction corpus and G10 exact wording tests; source diff review shows no added detector or severity/confidence/ID change |
| 16. Explanation seam | RULES documents 35 observation variants and four-question association; no catalog/renderer/title-dependent association is implemented |
| 17. Platform validation | CONTRIBUTING and workflow distinguish native tests from four CGO-disabled compile targets, minimum/current toolchains, local results and pending GitHub execution |
| 18. Scope/read-only | Git optional-lock/index-write tests, native source review, synthetic owned fixtures; no target mutations by audit or new external capability |
| 19. Claims/migration | README, ARCHITECTURE, CONTRIBUTING, SECURITY, migration, result/JSON/output/rules/claims docs and fixture provenance reviewed; frozen roadmap retained with historical claims qualified in CLAIMS |

Run the workflow's explicit integrated regex as well as full tests and race tests. The full suite is the G7–G11 regression gate; focused runs preserve test names and assertions. Repeated Linux race runs for `TestGitRunner_DescendantPipeCleanup` validate the readiness change without changing the production runner. Parent watchdogs remain even when readiness signaling is present.

All hostile fixtures are owned and synthetic. No real device creation, privilege, usable credential, network credential validation, dependency upgrade, new rule, config system, explanation implementation, GUI or scanner integration belongs to this checkpoint. Any discovered production process-cleanup defect requires a separate design/review stop, not an unannounced fix here.
