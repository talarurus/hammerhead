#!/usr/bin/env python3
"""Bounded synthetic demo and clean-prefix smoke of the packaged Core binary."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

archive_path = Path(sys.argv[1]).resolve()
assert archive_path.is_file(), archive_path
RULES = ["FILE-001", "FILE-002", "GIT-001", "PROJ-001", "PROJ-002", "SEC-001"]
checks = []
record_dir = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
if record_dir:
    record_dir.mkdir(parents=True, exist_ok=False)

def record(name, data):
    if record_dir:
        (record_dir / name).write_bytes(data)

with tempfile.TemporaryDirectory(prefix="hammerhead-core-smoke-") as temp:
    work = Path(temp)
    prefix = work / "install" / "bin"
    prefix.mkdir(parents=True)
    installed = prefix / "hammerhead-core"
    with tarfile.open(archive_path, "r:gz") as archive:
        member = archive.getmember("hammerhead-core")
        assert member.isfile() and member.size < 32 * 1024 * 1024
        with archive.extractfile(member) as source, installed.open("wb") as dest:
            shutil.copyfileobj(source, dest)
    installed.chmod(0o755)
    binary_hash = hashlib.sha256(installed.read_bytes()).hexdigest()
    marker = work / "sentinel-started"
    helpers = work / "helpers"
    helpers.mkdir()
    sentinel = '#!/bin/sh\nprintf "started\\n" >> "$CORE_SENTINEL"\nexit 91\n'
    for name in ["git", "git-credential-core-sentinel", "core-helper", "sh"]:
        helper = helpers / name
        helper.write_text(sentinel)
        helper.chmod(0o700)
    env = {
        "PATH": str(helpers), "NO_COLOR": "1", "CORE_SENTINEL": str(marker),
        "GIT_EXEC_PATH": str(helpers), "GIT_ASKPASS": str(helpers / "core-helper"),
        "GIT_SSH_COMMAND": str(helpers / "core-helper"),
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": str(helpers / "core-helper"),
    }
    control = subprocess.run([str(helpers / "git"), "--version"], env=env, timeout=5)
    assert control.returncode == 91 and marker.read_text() == "started\n"
    marker.unlink()
    checks.append("live sentinel positive control")

    def run(args, code=0):
        result = subprocess.run([str(installed), *map(str, args)], cwd=work,
                                env=env, capture_output=True, timeout=10)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        assert not marker.exists(), "Core started Git or a helper"
        return result

    def root(name):
        path = work / name
        path.mkdir()
        for file, text in {"README.md": "synthetic\n", "LICENSE": "synthetic\n",
                           ".gitignore": ".env\n*.key\nid_*\n"}.items():
            (path / file).write_text(text)
        return path

    def report(path, code=0, *extra):
        result = run(["audit", path, "--output", "json", *extra], code)
        data = json.loads(result.stdout)
        if code == 2:
            assert result.stderr.startswith(b"Error:") and result.stderr.count(b"\n") == 1
        else:
            assert not result.stderr
        assert data["product"] == "Hammerhead Core" and data["version"] == "0.2.0-core.1"
        assert data["schema"] == "hammerhead-core/v0.2"
        assert data["scope"]["included_rules"] == RULES
        omitted = data["scope"]["not_evaluated"]
        assert len(omitted) == 1 and omitted[0]["rule_id"] == "GIT-002"
        assert omitted[0]["status"] == "not_evaluated"
        assert "GIT-002" not in [f["rule_id"] for f in data["findings"]]
        return data

    version = run(["version"])
    assert b"Hammerhead Core version 0.2.0-core.1" in version.stdout
    for command in [["--help"], ["audit", "--help"]]:
        assert b"NOT EVALUATED" in run(command).stdout
    clean = root("clean")
    data = report(clean)
    assert data["status"] == "completed" and not data["findings"]
    assert data["summary"]["checks_attempted"] == 6
    assert sorted(c["rule_id"] for c in data["coverage"]["checks"]) == RULES
    assert all(c["status"] == "completed" for c in data["coverage"]["checks"])
    record("clean.json", json.dumps(data, indent=2).encode() + b"\n")
    checks.append("installed version/help, exact six-rule clean coverage, exit 0")

    for rule in RULES:
        fixture = root(rule)
        if rule == "FILE-001": (fixture / "id_rsa").write_text("synthetic filename only\n")
        if rule == "FILE-002": (fixture / "large.txt").write_text("a" * 2048)
        if rule == "GIT-001": (fixture / ".gitignore").unlink()
        if rule == "PROJ-001": (fixture / "README.md").unlink()
        if rule == "PROJ-002": (fixture / "go.mod").write_text("module synthetic.invalid/fixture\n")
        if rule == "SEC-001": (fixture / "notes.txt").write_text("-----BEGIN PRIVATE KEY-----\nSYNTHETIC HEADER ONLY\n")
        data = report(fixture, 1 if rule in ["FILE-001", "SEC-001"] else 0,
                      "--max-file-size", "1KB")
        assert data["status"] == "completed" and len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == rule
        record(rule + ".json", json.dumps(data, indent=2).encode() + b"\n")
    checks.append("separate positive fixtures for every included rule, exits 0/1")

    metadata = clean / ".git"
    metadata.mkdir()
    (metadata / "HEAD").write_text("ref: refs/heads/main\n")
    (metadata / "config").write_text("[core]\nrepositoryformatversion=0\nfsmonitor=" + str(helpers / "core-helper") + "\n[credential]\nhelper=!" + str(helpers / "core-helper") + "\n")
    assert not report(clean)["findings"]
    checks.append("synthetic Git metadata/helper settings cannot start sentinel")

    redacted = root("redaction")
    key = "AKIA0123456789ABCDEF"
    secret = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7b"
    (redacted / "settings.txt").write_text("aws_access_key_id=" + key + "\naws_secret_access_key=" + secret + "\n")
    for fmt in ["json", "terminal", "quiet"]:
        args = ["audit", redacted, "--quiet"] if fmt == "quiet" else ["audit", redacted, "--output", fmt]
        result = run(args, 1)
        combined = result.stdout + result.stderr
        assert b"SEC-001" in combined and key.encode() not in combined and secret.encode() not in combined
        if fmt != "json": assert b"GIT-002: NOT EVALUATED" in combined
        if fmt == "quiet": assert b"[STATUS] COMPLETED" in result.stderr
        record("redacted-" + fmt + ".stdout", result.stdout)
        record("redacted-" + fmt + ".stderr", result.stderr)
    assert report(redacted, 0, "--fail-on", "none")["status"] == "completed"
    checks.append("JSON/terminal/quiet redaction and fail-on none")

    incomplete = root("incomplete")
    (incomplete / ".gitignore").write_text("x" * 70000)  # Supported file, parser token limit exceeded.
    data = report(incomplete, 2, "--fail-on", "none")
    assert data["status"] == "partial" and not data["findings"]
    record("partial.json", json.dumps(data, indent=2).encode() + b"\n")
    assert any(c["rule_id"] == "GIT-001" and c["status"] == "partial" for c in data["coverage"]["checks"])
    run(["audit", incomplete, "--quiet", "--fail-on", "none"], 2)
    run(["audit", work / "missing", "--output", "json"], 2)
    run(["audit", clean, "--enable-git"], 2)
    assert not marker.exists()
    checks.append("required parsing incompleteness and invalid input exit 2; hidden Git switch rejected")

print(json.dumps({"status": "passed", "archive": str(archive_path),
                  "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                  "installed_binary_sha256": binary_hash, "checks": checks,
                  "qualification": "installation/demo only; native security acceptance is recorded separately in release review"}, indent=2))
