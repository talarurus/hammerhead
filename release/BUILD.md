# Reproduce this Core candidate

Use the verified explicit source archive/standalone workspace (without a `.git` directory) on native macOS ARM64 with the recorded Go 1.27.1 toolchain. The module minimum is 1.26.0, but builds using other toolchains/platforms are not the qualified candidate. Native Core acceptance passed on macOS 27.0.1 ARM64. Developer ID/notarization/Gatekeeper and earlier-OS qualification are not provided by this explicitly unsigned prerelease.

```sh
mkdir -p dist
CGO_ENABLED=0 go build -trimpath -o dist/hammerhead-core ./cmd/hammerhead-core
go vet ./...
go test -race -json -count=1 ./... > core-race.jsonl
python3 release/smoke.py dist/hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz
(cd dist && shasum -a 256 -c SHA256SUMS)
```

Existing modules must be available locally for offline reproduction. This session used `GOCACHE=/private/tmp/hammerhead-core-go-cache GOPROXY=off GOSUMDB=off`; Go did not fetch dependencies. `go mod verify` checked the pinned cache. A normal native user shell can use its own writable Go cache. The native handoff creates a fresh temporary build cache and disables dependency fetching.

The exact distribution packer is `package.py` (Python standard library). It packages only the native ARM64 executable plus scope/install/license/review documents, a source archive and a separate evidence archive. Archive metadata is normalized (mtime 0, uid/gid 0, stable modes/order; gzip mtime 0). The source manifest excludes generated artifacts, evidence, the preserved earlier candidate and itself; the source archive includes that manifest. `dist/provenance.json` binds the binary, source-manifest and archive hashes, build command/toolchain/base commit and native acceptance / unsigned approval status. `dist/SHA256SUMS` binds all public deliverables; `dist/LOCAL-SHA256SUMS` covers local-only artifacts too. These hashes are not signed attestations.

After collecting new native evidence or changing any source/document, rerun packaging and compare hashes before review. Public checksums use asset basenames and cover only the publication allowlist. A separate internal checksum file covers the local executable/evidence archive. The packer does not build, test, sign or publish. `qualify-macos.sh` is the only Terminal acceptance handoff and never changes the release decision automatically.

A Git-tag checkout may embed VCS metadata with the recorded default build flags; use the explicit source archive for the exact recorded unstamped rebuild. Packaging requires the preserved internal native evidence and refuses changes to accepted tested inputs. Public source recipients can independently build/test from the source archive; the included public review and accepted-input manifest identify the approved code.
