# Hammerhead Core 0.2.0-core.1 — macOS ARM64 installation

Native Core acceptance passed on **Apple Silicon macOS 27.0.1 (26A434)**. No earlier minimum macOS version, Intel Mac or Linux binary is qualified. This is a distinct Core prerelease, not the original full Hammerhead v0.2 release.

## Explicit unsigned option

This executable has an **ad hoc linker signature only**, with **no Apple Developer ID signature or notarization**. Gatekeeper acceptance and first launch of a downloaded/quarantined copy are unqualified; macOS or device policy may block execution. The local Gatekeeper assessment returned an internal Code Signing subsystem error. Users requiring Apple-verified publisher identity or notarization should wait for a signed distribution.

If macOS blocks execution, **stop**. Do not remove quarantine, disable Gatekeeper, re-sign the binary or override device policy as part of these instructions. SHA-256 checksums detect changed bytes and do not authenticate the publisher or establish Apple approval.

## Verify, extract and run

After founder approval and actual publication, obtain these two assets from the **Hammerhead Core 0.2.0-core.1** prerelease in `talarurus/hammerhead` (proposed tag `hammerhead-core-v0.2.0-core.1`):

- `hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz`
- `SHA256SUMS`

In the directory containing both downloads, verify the exact archive entry before extracting:

```sh
awk '$2 == "hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz" { print; matched=1 } END { if (!matched) exit 1 }' SHA256SUMS > binary.sha256
shasum -a 256 -c binary.sha256
core_extract=$(mktemp -d /tmp/hammerhead-core-install.XXXXXX)
tar -xzf hammerhead-core_0.2.0-core.1_darwin_arm64.tar.gz -C "$core_extract"
"$core_extract/hammerhead-core" version
"$core_extract/hammerhead-core" --help
```

Expected version: `Hammerhead Core version 0.2.0-core.1`; source base: `4fa1018b13ed4b8b6af194a326105e098dc8118f`. The version output also states **GIT-002: NOT EVALUATED**. Full source/artifact hashes and acceptance details are in `provenance.json`.

To keep the executable, move it into an existing writable bin directory, preserving its attributes and platform protections:

```sh
# Replace this path with your chosen existing writable directory.
core_bin_dir=/your/chosen/bin
test -d "$core_bin_dir" && test -w "$core_bin_dir"
test ! -e "$core_bin_dir/hammerhead-core"
mv "$core_extract/hammerhead-core" "$core_bin_dir/hammerhead-core"
"$core_bin_dir/hammerhead-core" version
"$core_bin_dir/hammerhead-core" audit /path/to/project --output json
```

Retain the package's license, notices and documentation alongside your installation records. Moving the binary does not qualify downloaded/quarantined launch behavior. No administrator access is required for a writable prefix. The distinct filename does not replace `hammerhead`. Remove the installed `hammerhead-core` file to uninstall.

Core includes six native checks. Advanced Git health, history/tracking and metadata execution are excluded. Read `README.md`, `SECURITY.md` and the versioned Core documentation for eligibility, exclusions, reporting and exit 0/1/2 semantics. Source builds are a separate trust decision, not an Apple notarization substitute; reproduce the recorded build from the verified source archive using Go 1.27.1.
