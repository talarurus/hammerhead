# Hammerhead Roadmap

This roadmap outlines the development trajectory for Hammerhead. Phases are ordered by architectural dependency and immediate user utility.

---

## Phase V0.1 — Foundations & Native Repository Auditing (Completed)

The focus of V0.1 was establishing a secure, fast, and reliable single-binary CLI with core native hygiene and security checks and a minimal dependency footprint.

### Milestone 1: Walking Skeleton
- [x] CLI entry point and Cobra argument parsing (`hammerhead audit [path]`, `version`)
- [x] Defense-in-depth filesystem traversal (`SafeWalker`) with symlink jail, depth limits, and exclusions
- [x] Normalized `Finding` model with severity, confidence, sanitized evidence, and remediation
- [x] Explicit check registry (`DefaultRegistry`) without `init()` registration side effects
- [x] Primary native check: Sensitive filename detection (`FILE-001`) covering SSH keys, `.env`, credentials, keystores
- [x] Terminal reporter with ANSI color coding and severity summaries
- [x] Structured JSON reporter (`--output json`)
- [x] Threshold-aware exit codes (`0`, `1`, `2` with `--fail-on`)
- [x] Foundational test harness with adversarial fixtures and race detection

### Milestone 2: Native Repository Hygiene & Hardening
- [x] **Large File Detection (`FILE-002`)**: Detect files in the audited directory exceeding configurable size thresholds (`--max-file-size`).
- [x] **Gitignore Hygiene Check (`GIT-001`)**: Verify common sensitive patterns (`.env`, `*.key`, `id_rsa`) are properly excluded without penalizing benign public certificates (`*.pem`).
- [x] **Repository Health Check (`GIT-002`)**: Inspect repository status, detached HEAD, and uncommitted modification states.
- [x] **Documentation & Governance Check (`PROJ-001`)**: Detect presence of `README.md` and `LICENSE`.
- [x] **Project / Runtime Detection (`PROJ-002`)**: Identify language runtimes, package managers, and manifest files (`go.mod`, `package.json`, `Cargo.toml`, etc.).
- [x] **Secret Signatures & Credential Pairs (`SEC-001`)**: Narrow regex checks for PEM private keys and AWS credentials, properly distinguishing Access Key IDs (Medium) from confirmed Access Key + Secret Key pairs (Critical).
- [x] **Finding Classification Architecture**: Strict separation of `ClassSecurity`, `ClassHygiene`, and `ClassInfo`. Repositories with zero security issues report `Security risk: NONE`.
- [x] **Terminal Injection Sanitization**: Strip ANSI escape sequences, carriage returns, embedded newlines, and control characters from untrusted repository paths and evidence strings.
- [x] **Path Exclusions (`--exclude` / `-e`)**: Repeatable traversal exclusion patterns evaluated before reading child directories.
- [x] **Quiet Output Mode (`--quiet` / `-q`)**: Compact single-line finding summaries for scripts and git hooks.

---

## Phase V0.2 — Orchestration, External Scanners & Configuration

Focus: Adding external security tool orchestration and repo configuration without compromising native execution.

- [ ] **Configuration File Support**: Optional `.hammerhead.yml` allowing users to define local exclusions, file-size limits, or custom fail thresholds.
- [ ] **External Scanner Interface**: Safe subprocess execution harness for third-party security utilities.
- [ ] **TruffleHog Integration**: Deep secret and commit-history scanning when TruffleHog binary is detected locally.
- [ ] **OSV-Scanner Integration**: Dependency vulnerability auditing via Google's OSV database.
- [ ] **Suppression / Baseline System**: Ability to suppress accepted risks or establish a baseline file to ignore legacy findings.
- [ ] **SARIF Reporter**: Output findings in OASIS SARIF format for native integration with GitHub Code Scanning.

---

## Phase V0.3+ — Environment Auditing & Developer Experience

Focus: Expanding beyond static repo inspection into local environment diagnostics and automated onboarding.

- [ ] **`hammerhead doctor`**:
  - Inspect local developer workstation configurations.
  - Verify Git identity, SSH key permissions, GPG signing configs.
  - Audit installed runtime versions, package managers, Docker socket permissions, and local security tools.
- [ ] **`hammerhead init`**:
  - Scaffold secure repository templates: `.gitignore`, `.editorconfig`, pre-commit hooks, and CI workflows.
- [ ] **Markdown & HTML Reporters**: Human-friendly exportable audit summaries.
- [ ] **Git Pre-commit Hook Integration**: Fast, staged-file audit mode for local git commits.

---

## Long-Term Vision

- [ ] **Hammerhead Agent / MCP Interface (`hammerhead agent`)**:
  - Expose Hammerhead capabilities via the Model Context Protocol (MCP) and JSON-RPC APIs.
  - Allow AI coding agents (Claude Code, Gemini/Antigravity, Codex) to invoke repository audits and query remediation plans programmatically.
- [ ] **Trivy / Container / IaC Scanning**: Orchestrate Trivy for container image and Terraform/CloudFormation auditing.
- [ ] **Homelab & Linux Diagnostic Profiles**: Diagnostic modules for home server and Linux host security hygiene.
