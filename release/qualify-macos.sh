#!/bin/sh
# One native Terminal handoff. No publishing, protected writes or test filtering.
set -eu
cd "$(dirname "$0")/.."
if [ "$(uname -sm)" != "Darwin arm64" ]; then
  echo 'NO-GO: this handoff requires a native macOS ARM64 host.' >&2
  exit 2
fi
if [ "$(go version)" != 'go version go1.27.1 darwin/arm64' ]; then
  echo 'NO-GO: install/use the recorded Go 1.27.1 darwin/arm64 toolchain first.' >&2
  exit 2
fi
evidence=$(mktemp -d /tmp/hammerhead-core-native.XXXXXX)
export GOCACHE="$evidence/go-cache"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
printf 'Evidence: %s\n' "$evidence"
{
  date -u
  uname -sm
  sw_vers
  go version
} > "$evidence/environment.txt"
# The manifest binds both acceptance source and package documentation.
shasum -a 256 -c release/source-manifest.sha256 > "$evidence/source-integrity.txt"
(cd dist && shasum -a 256 -c SHA256SUMS) > "$evidence/artifact-integrity.txt"
go mod verify > "$evidence/module-verify.txt"
status=0
if go vet ./... > "$evidence/vet.log" 2>&1; then
  echo 'vet: PASS'
else
  echo 'vet: FAIL'
  status=2
fi
if go test -race -json -count=1 ./... > "$evidence/core-race.jsonl" 2>&1; then
  echo 'full Core race suite (including sockets): PASS'
else
  echo 'full Core race suite (including sockets): FAIL'
  status=2
fi
if CGO_ENABLED=0 go build -trimpath -o "$evidence/rebuilt" ./cmd/hammerhead-core && cmp dist/hammerhead-core "$evidence/rebuilt"; then
  echo 'native rebuild matches candidate: PASS'
else
  echo 'native rebuild matches candidate: FAIL'
  status=2
fi
if python3 release/smoke.py dist/hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz "$evidence/demo" > "$evidence/install-smoke.json" 2>&1; then
  echo 'clean packaged install / synthetic demo: PASS'
else
  echo 'clean packaged install / synthetic demo: FAIL'
  status=2
fi
printf 'exit_status=%s\n' "$status" > "$evidence/outcome.txt"
if [ "$status" -eq 0 ]; then
  echo 'Native acceptance passed. Preserve this evidence for final release review.'
  echo 'Developer ID/notarization/Gatekeeper/minimum-OS qualification and distribution approval remain separate.'
else
  echo 'NO-GO: inspect the preserved failures; do not distribute.'
fi
printf 'Evidence: %s\n' "$evidence"
exit "$status"
