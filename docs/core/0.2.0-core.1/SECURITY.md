# Core security and platform boundaries

Native acceptance passed all 225 top-level Core tests on Apple Silicon macOS 27.0.1 (26A434), including symlinks, pinned-root/path replacement, FIFO/socket safety, required read/traversal failure, budgets, cancellation, redaction, output errors and fake Git/helper sentinels with positive controls. A byte-identical native rebuild, clean-prefix installation/demo, vet and module integrity checks passed.

The reviewed native filesystem implementation pins root descriptors, resolves components relative to them, checks identity/type and uses nonblocking/no-follow opens. Root pathname replacement does not redirect native authority. Reads and traversal remain bounded. These defenses do not provide an atomic content snapshot, a process sandbox, guaranteed interruption of kernel I/O, or assurance about omitted content, hard links and mount/filesystem behavior.

The Core source has no Git collector/health implementation and the linked graph has no `os/exec` or internal Git package. Checks receive no Git metadata authority. **GIT-002 is NOT EVALUATED**; advanced Git health, tracking/history and branch/worktree analysis are omitted. GIT-001 is textual root `.gitignore` hygiene only.

The distributed executable has an ad hoc linker signature, no Developer ID signature and no Apple notarization. Gatekeeper acceptance and quarantined-download first launch remain unqualified; macOS/device policy may block it. Installation supplies no platform-protection bypass. Checksums are integrity comparisons, not publisher authentication. Only macOS 27.0.1 ARM64 was natively qualified; the binary's minimum-load metadata does not qualify older macOS versions. Intel macOS and Linux are not offered.

Patterns, filenames and manifests are observations, not credential validity, pairing, compromise, license adequacy or complete repository security. Source/test details, licenses, provenance, release review and exact artifact hashes accompany this prerelease. The original full-Git release remains subject to its existing open/blocked issues.
