# Hammerhead Core 0.2.0-core.1 — final release review

**READY FOR EXPLICIT UNSIGNED PRERELEASE APPROVAL**

Mandatory blockers: **none**. Native Core security acceptance passed. The prepared macOS ARM64 release has no Developer ID signature or notarization; Gatekeeper acceptance is unqualified. Final founder approval is required before push, tag, GitHub release or website deployment.

## Verified native evidence

The supplied `/tmp/hammerhead-core-native.yiNhrz` was independently inspected before any release documentation changed. All source and artifact checksum checks passed. `outcome.txt` records exit_status=0; the shell handoff only writes 0 after vet, full race suite, native rebuild equality and packaged installation/demo succeed.

- **225 top-level tests passed**, zero failed or skipped acceptance tests; no test filters and no race detector report. Both `TestReader_SocketRejected` and `TestCLI_SpecialFileNoHang` passed. The command package's “no test files” event is not a test pass/skip.
- Full suite command: `go test -race -json -count=1 ./...`. All nine packages containing tests passed. Spawned normal CLI builds are standard executables; Go test processes and direct engine/application/CLI-context paths are race-instrumented.
- `go vet` passed with empty output; `go mod verify` reports all modules verified.
- The native rebuild is byte-identical to the release binary, SHA-256 `e84f47227839157c34650d9ccc6f9aa54e70512f33bf96b0854be910f7c06905`.
- The native clean-prefix installation/demo verified that exact binary and the accepted archive. It exercises every included rule, clean and threshold exits, partial/2 even with `--fail-on none`, redaction, scope and live Git/helper sentinels with positive controls.
- Actual native environment: Apple Silicon, macOS **27.0.1** build **26A434**, Go **1.27.1** darwin/arm64. No earlier minimum macOS version, Intel Mac or Linux platform is qualified.

The native log records that the filesystem rejected creation of an invalid-UTF-8 filename control. That unavailable on-disk control was not exercised as a walked filename; the test completed its remaining cases. Zero skipped tests refers to Go test events, not a claim that every impossible filename was representable.

Logs were copied to `release/evidence/native-acceptance/` without modifying the originals. The original accepted manifest and artifacts are preserved in `release/accepted-ship-core-01/`. Independent review details and tested-input hashes are in `release/evidence/final-review/`.

## Scope and source identity

Core includes exactly FILE-001, FILE-002, SEC-001, PROJ-001, PROJ-002 and textual GIT-001. **GIT-002 is explicitly NOT EVALUATED.** The Git collector package and health implementation are absent; the engine does not collect Git metadata. All-variant source tests, native runtime sentinel tests, a fresh dependency graph and actual binary symbol review establish that no Git/helper execution path is linked. There is no full-Git mode or fallback.

All 15 native filesystem production files remain byte-identical to protected commit `4fa1018b13ed4b8b6af194a326105e098dc8118f`. The six rule implementations and finding/collector support remain unchanged. Every accepted Go/test/fixture/module input is unchanged in the final source. Final edits affect release documentation, publication preparation and archive/provenance tooling only. No further full-suite rerun is required for those changes.

The Core acceptance matrix and explicitly excluded full-Git/historical tests are in `ACCEPTANCE.md`; excluded tests are not counted among the 225 native passes. This is limited native-rule qualification, not full repository security or the original full Hammerhead v0.2 release. A1-003 remains OPEN and original B4 remains BLOCKED for the full-Git release.

## Distribution and artifacts

See `DISTRIBUTION-REVIEW.md` for exact Apple command results. The ad hoc signature verifies structurally, but no usable Developer ID identity was found; notarization tools are installed but no submission is possible for the prepared ad hoc artifact. Gatekeeper assessment returned an internal subsystem error, leaving downloaded/quarantined launch behavior unqualified. No platform protection was bypassed.

The final binary archive contains the **same accepted executable** plus updated scope, installation, license and review documents. Its archive checksum changes because documentation changes. The source archive contains matching tested inputs and versioned Core documentation. The final wrapper receives one bounded installation/demo check; accepted security tests are reused.

Public assets and hashes are listed in `dist/SHA256SUMS`; `dist/provenance.json` binds archive hashes, executable identity and native acceptance. Raw internal evidence is retained locally and in a separately labelled internal evidence archive, outside the publication allowlist. SHA-256 is integrity evidence, not publisher authentication.

`GITHUB-PRERELEASE.md` is ready to use as the GitHub notes body. `PUBLICATION.md` gives exact gated source-branch/tag/release actions. `WEBSITE-PROPOSAL.md` contains copy and route/link changes for review only. No publication or deployment has occurred.

## Earlier failures

The initial sandbox race run had 223 passes and two socket fixture failures caused by denied socket operations. Those failures remain in `release/evidence/core-regression-race-final.jsonl`; the supplied native run resolves them without changing the tested code. Initial adaptation compile/golden issues, an unused test import and the demo's overstrict empty-stderr assertion remain recorded in their original logs. The corrected executable/demo behavior passed native acceptance; no failure record was deleted or relabelled as a pass.
