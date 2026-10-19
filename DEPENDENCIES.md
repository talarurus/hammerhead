# Dependency and license inventory

The actual macOS ARM64 executable was built using Go 1.27.1, CGO_ENABLED=0. `go version -m` identifies three linked external modules. Licenses and applicable patent notices are copied verbatim from the pinned module cache/toolchain into `THIRD-PARTY-LICENSES`. The scanner's own source is Apache-2.0, retained from the protected base.

| Component | Version | Relationship to ARM64 artifact | License / notice |
|---|---|---|---|
| Go runtime / standard library | go1.27.1 | Linked toolchain/runtime; MIME detection is local `http.DetectContentType` | BSD-3-Clause; Go LICENSE/PATENTS and standard-library vendored x/net, x/text, x/sys, x/crypto notices |
| github.com/spf13/cobra | v1.9.1 | Linked CLI | Apache-2.0; cobra-LICENSE.txt |
| github.com/spf13/pflag | v1.0.6 | Linked CLI options | BSD-3-Clause; pflag-LICENSE.txt |
| golang.org/x/sys | v0.48.0 | Linked rooted filesystem primitives | BSD-3-Clause; x-sys LICENSE and PATENTS |
| github.com/inconshreveable/mousetrap | v1.1.0 | Declared indirect module; Windows-only Cobra integration, **not linked in this macOS artifact** | Apache-2.0; mousetrap-LICENSE.txt |

`go.mod`/`go.sum` are unchanged from the protected commit. `release/evidence/modules.json` records the complete resolved module graph, including metadata-only Cobra documentation/test dependencies (go-md2man, blackfriday, yaml.v3, check.v1). These are not linked or vendored in this artifact. `production-dependencies.txt` records the actual executable package graph; `build-info.txt` records the linked module versions and h1 sums. `go mod verify` passed against the existing pinned cache with network access disabled.

No Git, Betterleaks, OSV, Trivy, credential helper or other scanning executable is bundled or invoked. No new module was added. The macOS linker supplied an ad hoc signature (no Team Identifier); this is not Developer ID signing or notarization. This is an inventory and integrity verification, not a vulnerability advisory audit or a certification of license suitability.
