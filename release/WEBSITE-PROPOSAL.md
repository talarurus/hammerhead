# Proposed talarurus.com/hammerhead/ update — review only

No website file was changed or deployed. This proposal is based on the local `talarurus.com/hammerhead/` pages; the live URL could not be retrieved by the web tool in this session. Preserve historical v0.1.0 releases, demonstration content and captures.

## Ready-to-use product copy

- Title / social title: **Hammerhead Core | Talarurus**
- Description: **Hammerhead Core 0.2.0-core.1: six native filesystem checks, redacted findings and explicit scan coverage. macOS ARM64 unsigned prerelease; advanced Git health is not included.**
- Badge: **0.2.0-core.1 · Core prerelease · Unsigned**
- Heading: **Inspect local files. Review concrete findings.**
- Lead: **Hammerhead Core checks sensitive filenames, large files, supported secret patterns, project hygiene and runtime manifests. Its root .gitignore check is textual only. Terminal and JSON reports show scope, coverage and incomplete work.**
- Availability: **Native Core acceptance passed on Apple Silicon macOS 27.0.1. No Developer ID signature or Apple notarization. Gatekeeper acceptance is unqualified; macOS may block this download. Older macOS, Intel Mac and Linux releases are unqualified.**
- Prominent scope disclosure beside the download: **GIT-002: NOT EVALUATED. Advanced Git health, native Git metadata collection, branch/worktree status and tracking/history analysis are not included. This is not the original full Hammerhead v0.2 release or complete repository security.**
- Primary action, only after actual publication: **macOS ARM64 — unsigned prerelease** → version-specific GitHub release page below.
- Secondary action: **Read Core 0.2.0-core.1 documentation** → `/hammerhead/docs/core/0.2.0-core.1/`.

## Concrete route changes after separate deployment approval

| Route | Proposed change |
|---|---|
| `/hammerhead/` | Replace current preview hero/version and seven-check navigation/table with Core copy and six included rows. Put omitted GIT-002 in a clearly separate NOT EVALUATED notice. Use `hammerhead-core` commands and `hammerhead-core/v0.2` schema. |
| `/hammerhead/release/` | Offer only the actual macOS ARM64 unsigned archive plus source/docs/checksums/provenance/license assets. Show qualification as macOS 27.0.1 ARM64 only. Keep Intel/Linux downloads inactive. Place unsigned/Gatekeeper limits before the action. |
| `/hammerhead/docs/` | Link prominently to versioned Core docs; label the original seven-rule full-Git developer preview as historical/unqualified. Remove the full-Git base-commit build recipe from the current Core install path. |
| `/hammerhead/docs/core/0.2.0-core.1/` | Add the prepared versioned docs from the release source. Include rules, usage/exits, JSON identity, security boundaries, unsigned installation and tested OS. |
| `/assets/products/hammerhead/core/0.2.0-core.1/` | Add reviewed actual native demo captures, retaining original evidence bytes. If absolute temporary roots are normalized for display, label that transformation. Do not relabel older preview output as Core. |

Use actual native `demo/clean.json`, per-rule captures and redacted reports; Core scope and GIT-002 non-evaluation must remain visible. Preserve the existing historical v0.1.0 demonstration as historical. Do not imply that Core clears the full-Git A1-003/B4 issues.

## Exact intended destinations (activate only after publication)

- Release: `https://github.com/talarurus/hammerhead/releases/tag/hammerhead-core-v0.2.0-core.1`
- Binary: `https://github.com/talarurus/hammerhead/releases/download/hammerhead-core-v0.2.0-core.1/hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz`
- Source: same download prefix + `hammerhead-core_0.2.0-core.1_source.tar.gz`
- Versioned docs: same download prefix + `hammerhead-core_0.2.0-core.1_docs.tar.gz`
- Integrity/provenance: same prefix + `SHA256SUMS` and `provenance.json`
- Attribution: same prefix + `LICENSE`, `NOTICE` and `DEPENDENCIES.md`

Before activation, verify the actual returned GitHub release/tag/asset identities and public downloaded checksums. Do not publish a moving “latest” download link. The GitHub prerelease must use a distinct Core tag and must not replace or relabel the original full-Git release or any historical release. Website deployment requires separate explicit founder approval; no deployment command is executed or implied by the GitHub approval action.
