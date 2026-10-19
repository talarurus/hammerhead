#!/usr/bin/env python3
"""Package the accepted Core binary, public source/docs and unsigned provenance. No publishing."""
from pathlib import Path
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
VERSION = "0.2.0-core.1"
BASE = "4fa1018b13ed4b8b6af194a326105e098dc8118f"
DECISION = "READY FOR EXPLICIT UNSIGNED PRERELEASE APPROVAL"
DIST = Path("dist")
BINARY = DIST / "hammerhead-core"

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

# Reuse verified native acceptance; a changed tested input is a hard stop.
accepted = Path("release/evidence/native-acceptance")
assert (accepted / "outcome.txt").read_text().strip() == "exit_status=0"
review = json.loads(Path("release/evidence/final-review/native-verification.json").read_text())
assert sha(BINARY) == review["binary_sha256"]
inputs = Path("release/evidence/final-review/tested-inputs.sha256").read_text()
for line in inputs.splitlines():
    expected, name = line.split("  ", 1)
    assert sha(name) == expected, "Accepted tested input changed: " + name
assert hashlib.sha256(inputs.encode()).hexdigest() == review["tested_input_manifest_sha256"]
assert "Mach-O 64-bit executable arm64" in subprocess.check_output(["file", str(BINARY)], text=True)
assert VERSION in subprocess.check_output([str(BINARY.resolve()), "version"], text=True)
build_info = subprocess.check_output(["go", "version", "-m", str(BINARY)], text=True)
assert build_info.splitlines()[0].endswith(": go1.27.1")
assert "CGO_ENABLED=0" in build_info and "GOARCH=arm64" in build_info and "GOOS=darwin" in build_info

# Compact public review; raw machine/keychain logs remain internal evidence.
public_review = {
    "product": "Hammerhead Core", "version": VERSION, "decision": DECISION,
    "mandatory_blockers": [], "approval": "founder approval pending; nothing published",
    "source_base_commit": BASE, "binary_sha256": sha(BINARY),
    "native_acceptance": {"exit_status": 0, "top_level_passed": 225, "failed": 0,
        "skipped_tests": 0, "filters": None, "race_reported": False,
        "race_log_sha256": sha(accepted / "core-race.jsonl"),
        "outcome_sha256": sha(accepted / "outcome.txt"),
        "install_demo_log_sha256": sha(accepted / "install-smoke.json"),
        "accepted_source_manifest_sha256": review["accepted_source_manifest_sha256"],
        "tested_inputs_sha256": review["tested_input_manifest_sha256"],
        "tested_inputs_unchanged": True},
    "native_qualified_environment": {"os": "macOS 27.0.1", "build": "26A434", "architecture": "arm64", "toolchain": "go1.27.1"},
    "earlier_macos_minimum_qualified": False, "intel_or_linux_qualified": False,
    "signing": "linker ad hoc only; no Developer ID; no notarization",
    "gatekeeper": {"qualified": False, "assessment_exit": 1, "assessment_result": "internal error in Code Signing subsystem", "quarantined_download_launch_qualified": False},
    "included_rules": ["FILE-001", "FILE-002", "GIT-001", "PROJ-001", "PROJ-002", "SEC-001"],
    "not_evaluated": [{"rule_id": "GIT-002", "status": "not_evaluated", "reason": "Advanced Git health and native Git metadata execution are excluded"}],
    "limits": "Not full seven-rule coverage, complete repository security or the original full Hammerhead v0.2 release",
}
Path("release/FINAL-REVIEW.json").write_text(json.dumps(public_review, indent=2) + "\n")
shutil.copy2("release/FINAL-REVIEW.json", DIST / "RELEASE-REVIEW.json")
shutil.copy2("release/evidence/final-review/tested-inputs.sha256", "release/accepted-inputs.sha256")

def pack(path, items):
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for source, name in sorted(items, key=lambda item: item[1]):
                    info = archive.gettarinfo(str(source), arcname=name)
                    assert info.isfile(), source
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if source == BINARY else 0o644
                    with source.open("rb") as data:
                        archive.addfile(info, data)

manifest = Path("release/source-manifest.sha256")
source_files = sorted(p for p in Path(".").rglob("*") if p.is_file()
    and p.parts[0] not in ("dist", ".git", "__pycache__") and "__pycache__" not in p.parts
    and not str(p).startswith(("release/evidence/", "release/accepted-ship-core-01/")) and p != manifest)
manifest.write_text("".join(f"{sha(p)}  {p}\n" for p in source_files))
source_archive = DIST / f"hammerhead-core_{VERSION}_source.tar.gz"
pack(source_archive, [(p, f"hammerhead-core-{VERSION}/{p}") for p in [*source_files, manifest]])

documents = [Path(p) for p in ["README.md", "INSTALL.md", "LICENSE", "NOTICE", "SECURITY.md",
    "RELEASE-NOTES.md", "DEPENDENCIES.md", "ARCHITECTURE.md", "release/ACCEPTANCE.md",
    "release/RESULTS.md", "release/BUILD.md", "release/DISTRIBUTION-REVIEW.md", "release/FINAL-REVIEW.json"]]
version_docs = sorted(p for p in Path(f"docs/core/{VERSION}").rglob("*") if p.is_file())
licenses = sorted(Path("THIRD-PARTY-LICENSES").glob("*"))
binary_archive = DIST / f"hammerhead-core_{VERSION}_darwin_arm64.tar.gz"
pack(binary_archive, [(BINARY, "hammerhead-core")] + [(p, str(p)) for p in documents + version_docs + licenses])
docs_archive = DIST / f"hammerhead-core_{VERSION}_docs.tar.gz"
pack(docs_archive, [(p, str(p)) for p in version_docs + documents + licenses])
# Evidence is preserved locally, deliberately absent from the public asset allowlist.
evidence_archive = DIST / f"hammerhead-core_{VERSION}_evidence.tar.gz"
pack(evidence_archive, [(p, str(p)) for p in sorted(Path("release/evidence").rglob("*")) if p.is_file()])
for name in ["LICENSE", "NOTICE", "DEPENDENCIES.md"]:
    shutil.copy2(name, DIST / name)

archives = [binary_archive, source_archive, docs_archive]
provenance = DIST / "provenance.json"
provenance.write_text(json.dumps({
    "product": "Hammerhead Core", "version": VERSION, "proposed_tag": "hammerhead-core-v" + VERSION,
    "source_base_commit": BASE, "source_commit": None,
    "source_commit_note": "Standalone snapshot; a distinct Core branch/commit/tag will be created only after approval",
    "platform": "darwin/arm64", "toolchain": "go1.27.1", "cgo_enabled": False,
    "build_command": "CGO_ENABLED=0 go build -trimpath -o dist/hammerhead-core ./cmd/hammerhead-core",
    "binary_sha256": sha(BINARY), "source_manifest_sha256": sha(manifest),
    "archives": {p.name: sha(p) for p in archives},
    "qualification": DECISION, "mandatory_blockers": [],
    "native_acceptance": public_review["native_acceptance"],
    "qualified_environment": public_review["native_qualified_environment"],
    "signing": public_review["signing"], "gatekeeper": public_review["gatekeeper"],
    "included_rules": public_review["included_rules"], "not_evaluated": public_review["not_evaluated"],
    "public_review_sha256": sha(DIST / "RELEASE-REVIEW.json"),
    "final_documentation_change": "Release documentation, versioned docs and packaging/publication preparation only; accepted executable and tested inputs unchanged",
    "publisher_authentication": "Unsigned checksum/provenance documents are integrity evidence, not publisher authentication",
}, indent=2) + "\n")
public = [*archives, provenance, DIST / "RELEASE-REVIEW.json", *[DIST / p for p in ["LICENSE", "NOTICE", "DEPENDENCIES.md"]]]
(DIST / "SHA256SUMS").write_text("".join(f"{sha(p)}  {p.name}\n" for p in public))
local = [BINARY, evidence_archive, *public, DIST / "SHA256SUMS"]
(DIST / "LOCAL-SHA256SUMS").write_text("".join(f"{sha(p)}  {p}\n" for p in local))
print(json.dumps({"decision": DECISION, "public_assets": [p.name for p in public] + ["SHA256SUMS"], "binary_sha256": sha(BINARY)}, indent=2))
