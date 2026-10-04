# Hammerhead

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](go.mod)
[![CI](https://github.com/ammaarrehman/hammerhead/actions/workflows/ci.yml/badge.svg)](https://github.com/ammaarrehman/hammerhead/actions/workflows/ci.yml)

**Hammerhead** is a lightweight developer-security and repository hygiene CLI designed to inspect codebases for immediate security risks, exposed credentials, hygiene oversights, and ecosystem metadata. It emphasizes fast execution (<15ms), defense-in-depth safety when auditing untrusted code, deterministic rule evaluation, and clear separation between actionable security vulnerabilities and repository hygiene.

---

## Status: V0.1

Hammerhead V0.1 is the initial public release. It focuses on single-binary fast audits, defense-in-depth repository traversal (`SafeWalker`), 7 native security and hygiene checks, strict finding classification, terminal string sanitization, path exclusions, configurable thresholds, quiet script-friendly execution, and threshold-aware exit codes for CI/CD gates.

---

## What Hammerhead Does

- **Fast Local Audits**: Quickly scans repositories in milliseconds with zero external network calls or heavy background services.
- **Defensive Traversal**: Safely walks untrusted codebases using `SafeWalker`, enforcing symlink containment within the repository root, directory depth limits, file count caps, and read size limits.
- **Sensitive File & Credential Detection**: Identifies exposed private keys, credential configurations (`.env`), and high-confidence secret patterns (such as AWS credentials and PEM private key headers).
- **Repository Hygiene Verification**: Verifies `.gitignore` exclusions for sensitive files, identifies repository governance files (`README.md`, `LICENSE`), and flags oversized files.
- **Ecosystem Discovery**: Detects project runtimes and package manifests (`go.mod`, `package.json`, `Cargo.toml`, etc.).
- **Terminal Injection Protection**: Sanitizes all file paths and evidence strings before terminal rendering to prevent ANSI escape injection and terminal prompt spoofing.
- **CI/CD Integration**: Supports threshold-aware exit codes (`--fail-on`), script-friendly `--quiet` mode, and structured machine-readable JSON output (`--output json`).

---

## What Hammerhead Does NOT Do

Hammerhead is designed as a fast first-line triage and developer hygiene scanner. To maintain clarity and prevent false assurances:

- **Does NOT replace TruffleHog**: Hammerhead does not perform full Git revision history entropy scans, nor does it make outbound network API calls to verify whether detected secrets are active or revoked.
- **Does NOT replace Trivy**: Hammerhead does not parse lockfiles against deep vulnerability databases (CVEs) or scan container images and OS packages for known software vulnerabilities.
- **Does NOT replace Semgrep or mature SAST suites**: Hammerhead does not perform Abstract Syntax Tree (AST) parsing, control-flow analysis, taint tracking, or semantic code analysis.
- **Does NOT replace mature dedicated security scanners**: Hammerhead does not replace specialized enterprise vulnerability scanners, DAST tools, or compliance audit platforms.
- **Does NOT execute scanned code**: Hammerhead never executes build scripts, package managers, hooks, or binaries found inside audited repositories.

---

## Installation

### From Pre-Built Binaries

Download pre-compiled binaries for Linux and macOS (amd64 / arm64) from the [Releases](https://github.com/ammaarrehman/hammerhead/releases) page.

### Using `go install`

```bash
go install github.com/ammaarrehman/hammerhead/cmd/hammerhead@latest
```

### Building From Source

Prerequisites: Go 1.26+ and Git.

```bash
git clone https://github.com/ammaarrehman/hammerhead.git
cd hammerhead
make build
```

The compiled binary will be placed in the current directory as `hammerhead`.

---

## Quick Start

Audit the current repository with default settings:

```bash
hammerhead audit .
```

Audit a specific target directory:

```bash
hammerhead audit /path/to/project
```

Exclude specific directories or patterns:

```bash
hammerhead audit . --exclude testdata/repos/dirty -e vendor -e "*.min.js"
```

Run in quiet mode (prints only findings and summary, omitting verbose banners):

```bash
hammerhead audit . --quiet
```

Output machine-readable JSON:

```bash
hammerhead audit . --output json
```

---

## Example Terminal Output

When auditing a repository containing both security exposures and hygiene observations:

```text
================================================================================
HAMMERHEAD SECURITY & HYGIENE AUDIT
Target: /workspace/sample-project
================================================================================

[HIGH] Private key committed: server.key
  Rule ID:     FILE-001
  Class:       Security
  Category:    files
  Path:        certs/server.key
  Evidence:    File matches sensitive pattern: *.key
  Description: Private keys grant cryptographic identity and access. If committed,
               they must be treated as permanently compromised.
  Remediation: Remove the private key from version control, rotate the key
               immediately, and add '*.key' to .gitignore.

[HIGH] AWS Credential Pair exposed
  Rule ID:     SEC-001
  Class:       Security
  Category:    secrets
  Path:        .env:3
  Evidence:    AWS Access Key ID (AKIAIOSFODNN7EXAMPLE) with Secret Access Key present
  Description: Plaintext AWS credentials committed to source code grant immediate
               API access.
  Remediation: Immediately revoke and rotate the AWS credentials via AWS IAM.
               Store credentials in environment variables or an external secret vault.

[LOW] Sensitive pattern missing from .gitignore: Environment files
  Rule ID:     GIT-001
  Class:       Hygiene
  Category:    git
  Path:        .gitignore
  Evidence:    Missing rule for: .env
  Description: The repository's .gitignore file does not exclude environment files (.env).
  Remediation: Add '.env' to .gitignore.

[INFO] Runtime detected: Go
  Rule ID:     PROJ-002
  Class:       Info
  Category:    project
  Path:        go.mod
  Evidence:    Found go.mod
  Description: Detected Go project.

--------------------------------------------------------------------------------
AUDIT SUMMARY
--------------------------------------------------------------------------------
Total Findings: 4 (Security: 2, Hygiene: 1, Info: 1)
Overall Security Risk: HIGH
Checks Executed: 7
Result: FAILED (2 findings met or exceeded threshold 'high')
```

---

## The 7 Native Checks

Hammerhead ships with 7 deterministic native checks:

| Check ID | Name | Class | Category | Description |
|:---|:---|:---|:---|:---|
| **`FILE-001`** | Sensitive Files | `Security` | `files` | Detects accidentally committed private keys (`id_rsa`, `*.key`), environment configurations (`.env`), and credential files. |
| **`FILE-002`** | Large Files | `Hygiene` | `files` | Identifies files exceeding size thresholds (default 50 MB) to prevent repository bloat and accidental asset commits. |
| **`GIT-001`** | Gitignore Hygiene | `Hygiene` | `git` | Verifies `.gitignore` excludes common sensitive file patterns (`.env`, `*.key`, `id_rsa`) without penalizing benign public certificates. |
| **`GIT-002`** | Git Health | `Info` | `git` | Evaluates Git repository state (uncommitted modifications, untracked files) to provide clean context for audits. |
| **`PROJ-001`** | Repo Hygiene | `Hygiene` | `project` | Checks for standard open-source governance and documentation files (`README.md`, `LICENSE`). |
| **`PROJ-002`** | Runtime Detection | `Info` | `project` | Detects project ecosystems and manifests (`go.mod`, `package.json`, `Cargo.toml`, `requirements.txt`, etc.). |
| **`SEC-001`** | Secret Content | `Security` | `secrets` | Scans file contents for high-confidence cryptographic private key headers and AWS credentials (differentiating Access Key IDs from confirmed Credential Pairs). |

---

## Security vs Hygiene vs Informational Classification

Hammerhead strictly enforces three distinct finding classes to prevent noise and eliminate false alarm build breaks:

1. **`ClassSecurity` (`Security`)**: Genuine security vulnerabilities that pose direct operational or cryptographic risk (e.g., exposed private keys, AWS access keys, plaintext credential files). Only `ClassSecurity` findings can trigger build failures under `--fail-on`.
2. **`ClassHygiene` (`Hygiene`)**: Repository engineering quality observations that do not constitute direct security exposures (e.g., missing `.gitignore` entries, missing `README.md` or `LICENSE`, files exceeding size thresholds). Hygiene findings are highlighted for developer cleanup but never fail security thresholds.
3. **`ClassInfo` (`Info`)**: Contextual observations about the codebase (e.g., detected project runtimes, Git status of untracked files).

---

## CLI Reference

### Command Syntax

```bash
hammerhead audit [path] [flags]
hammerhead version
hammerhead help
```

### Flags for `audit`

| Flag | Shorthand | Default | Description |
|:---|:---:|:---:|:---|
| `--exclude` | `-e` | `[]` | Exclude paths or glob patterns (can be specified multiple times). |
| `--fail-on` | | `"high"` | Minimum security severity to trigger exit code 1 (`critical`, `high`, `medium`, `low`, `info`, `none`). |
| `--max-file-size` | | `"50MB"` | Maximum file size threshold for `FILE-002` and maximum file read size (e.g., `10MB`, `500KB`). |
| `--output` | `-o` | `"terminal"` | Output format: `terminal` or `json`. |
| `--quiet` | `-q` | `false` | Suppress non-essential informational messages and banners for clean scripting. |
| `--help` | `-h` | | Display help information for the command. |

---

## Exit Codes

Hammerhead returns predictable, threshold-aware exit codes:

| Exit Code | Status | Meaning |
|:---:|:---:|:---|
| **`0`** | **PASS** | Audit completed successfully. No security findings met or exceeded the configured `--fail-on` threshold. |
| **`1`** | **FAIL** | Audit completed successfully, but one or more `ClassSecurity` findings met or exceeded the configured `--fail-on` threshold. |
| **`2`** | **ERROR** | An operational or internal error prevented audit execution (e.g., directory does not exist, unreadable target, invalid CLI flags). |

### Configuring `--fail-on`

The `--fail-on` flag controls the severity threshold for exit code `1`:
- `--fail-on critical`: Fail only on `CRITICAL` security findings.
- `--fail-on high` *(default)*: Fail on `HIGH` or `CRITICAL` security findings.
- `--fail-on medium`: Fail on `MEDIUM`, `HIGH`, or `CRITICAL` security findings.
- `--fail-on low`: Fail on `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` security findings.
- `--fail-on info`: Fail on any security finding.
- `--fail-on none`: Never exit with code 1 due to findings (informational mode).

> [!NOTE]
> `--fail-on` applies exclusively to `ClassSecurity` findings. Hygiene and Info findings will never trigger an exit code of `1`.

---

## JSON Output

When invoked with `--output json`, Hammerhead produces structured JSON suitable for CI/CD ingestion, security dashboards, and automated agent workflows:

```json
{
  "schema": "hammerhead/v0.1",
  "timestamp": "2026-10-04T18:00:00Z",
  "version": "0.1.0-dev",
  "repository": {
    "root": "/workspace/sample-project"
  },
  "summary": {
    "total_findings": 1,
    "checks_run": 7,
    "security_risk": "high",
    "max_severity": "high",
    "security_findings_count": 1,
    "hygiene_findings_count": 0,
    "info_findings_count": 0,
    "by_severity": {
      "high": 1
    },
    "by_class": {
      "security": 1
    }
  },
  "findings": [
    {
      "id": "e2a1b4c8d9e0...",
      "rule_id": "FILE-001",
      "class": "security",
      "category": "files",
      "severity": "high",
      "confidence": "high",
      "title": "Private key committed: server.key",
      "description": "Private keys grant cryptographic identity and access...",
      "remediation": "Remove the private key from version control...",
      "path": "certs/server.key",
      "evidence": "File matches sensitive pattern: *.key",
      "source": "hammerhead",
      "check_version": "0.1.0"
    }
  ]
}
```

---

## Threat Model & Untrusted Repositories

Hammerhead is designed under the assumption that audited repositories may be untrusted, adversarial, or actively malicious. The engine enforces multiple defense-in-depth layers:

- **Root Containment (Symlink Jail)**: Symlinks are resolved using `filepath.EvalSymlinks` and validated against the repository root. Any symlink attempting to escape the root boundary is skipped and recorded.
- **Path Traversal Defense**: All relative paths are checked for `..` components before access.
- **Resource Exhaustion Bounds**: Enforces maximum directory recursion depth (default 50), maximum discovered file count (default 100,000), and per-file read limits (default 10 MB or `--max-file-size`) to guard against decompression bombs and directory recursion loops.
- **Terminal Injection Sanitization**: All repository-derived strings (file paths, evidence excerpts, git branches) are stripped of ANSI escape sequences, carriage returns, embedded newlines, and control codes before printing, preventing terminal manipulation or spoofed prompt attacks.
- **Zero Execution Policy**: Hammerhead never executes build systems, package managers, scripts, or hooks found within the audited repository. Subprocesses (e.g. Git status) are invoked directly with repository-controlled configuration flags disabled.
- **Default Noise Exclusions**: Metadata and third-party dependency caches (`.git`, `node_modules`, `vendor`, `.venv`, etc.) are automatically skipped during traversal.

---

## Limitations

As a V0.1 release, Hammerhead has specific architectural limitations:

- **Static Heuristic Matching**: Content checks rely on regex and structural pattern matching. They do not perform semantic analysis, AST decompilation, or data-flow tracking.
- **Non-Exhaustive Secret Coverage**: V0.1 focuses on high-confidence secret patterns (cryptographic keys, AWS tokens). It does not attempt to detect every proprietary token format.
- **No Git History Search**: Traversal inspects the current repository working tree on disk. It does not iterate through historic Git commit trees.
- **Uncompressed Files Only**: Scans plaintext source files; it does not unpack archive formats (`.zip`, `.tar.gz`, `.jar`).
- **Local Host Execution**: Does not connect to live identity providers or third-party APIs to validate whether exposed credentials are active.

---

## Comparison & Relationship to Mature Tools

Hammerhead is designed to complement existing security tooling, not replace mature specialized engines:

| Feature / Capability | Hammerhead (V0.1) | TruffleHog | Trivy | Semgrep |
|:---|:---:|:---:|:---:|:---:|
| **Primary Focus** | Fast developer triage & hygiene | Deep secret scanning | Vulnerability & container scanning | Semantic AST code analysis |
| **Startup / Scan Latency** | Milliseconds (<15ms) | Moderate | Moderate to High | Moderate |
| **Dependency Footprint** | Single static binary (Go) | Python / Go binary | Heavy engine + vulnerability DB | Python / OCaml binary |
| **Git Revision History** | Working tree only | Full git history | Working tree / containers | Working tree |
| **Live Credential Verification** | No | Yes (active API validation) | No | No |
| **CVE & Lockfile Auditing** | No | No | Yes | Yes (Semgrep Supply Chain) |
| **AST / Data-Flow Analysis** | No | No | No | Yes |
| **Untrusted Repo Hardening** | Built-in (`SafeWalker`, ANSI sanitization) | Variable | Container-focused | Engine-hardened |
| **Hygiene & Metadata Classification** | First-class separation | No | Limited | No |

### How to Use Hammerhead in Your Toolchain

- Use **Hammerhead** as a lightning-fast local pre-commit hook, fast PR gate, or agent workflow tool for instantaneous developer feedback.
- Use **TruffleHog** in comprehensive CI/CD pipelines to audit complete git history and verify active credentials with identity providers.
- Use **Trivy** in packaging pipelines to check dependencies against CVE registries and audit container images.
- Use **Semgrep** in code review pipelines for complex syntactic pattern matching and vulnerability taint analysis.

---

## License

Hammerhead is licensed under the [Apache 2.0 License](LICENSE).
