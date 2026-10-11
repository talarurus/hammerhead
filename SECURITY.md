# Security Policy

The Hammerhead project takes the security of its code and its users seriously. As a tool designed to inspect potentially untrusted repositories, Hammerhead treats defensive integrity as a primary design requirement.

## Supported Versions

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest patch release on the current minor branch receives security updates. `0.2.0-dev` is unreleased development on the Talarurus repository, not a published or newly supported v0.2 release. Historical v0.1.0 downloads and its original module identity remain unchanged.

## Reporting a Vulnerability

> [!WARNING]
> **Do not open public GitHub issues or discussions** to report security vulnerabilities, active exploits, or real credential exposures.

If you believe you have discovered a security vulnerability in Hammerhead:

1. **GitHub Private Vulnerability Reporting (Preferred)**: Navigate to the repository's **Security** tab, select **Advisories**, and click **Report a vulnerability**. This allows private communication and coordinated disclosure.
2. **Direct Contact**: If private vulnerability reporting is unavailable, contact the maintainer directly at `ammaar2rehman@gmail.com` with `[Hammerhead Security]` in the subject line.

### What to Include

To help us assess and remediate the issue effectively, please include:
- A clear description of the vulnerability and its potential security impact.
- Step-by-step reproduction instructions or a minimal proof of concept (PoC).
- Affected version(s), platform/OS, and CLI flags used.
- Any proposed fix, patch, or mitigation strategy if available.

### Scope

**In Scope:**
- Path traversal vulnerabilities allowing read access outside the specified repository root.
- Arbitrary code execution triggered by auditing untrusted files or repositories.
- Terminal injection vulnerabilities where malicious repository content bypasses terminal sanitization.
- Denial of service (infinite recursion, unbounded memory allocation, symlink loop hangs) during repository traversal.
- Exposure of sensitive internal memory or leakage of secret material in reports.

**Out of Scope:**
- Attacks requiring existing root, physical, or compromised shell access to the host machine running the CLI.
- Theoretical issues reported by automated scanners without a practical proof of concept.
- Undetected secrets or patterns (please open standard feature requests or pull requests to expand check coverage).
- Social engineering against maintainers.

## Response Expectations

We aim to:
- Acknowledge receipt of vulnerability reports within 3 business days.
- Provide an initial technical assessment confirming or clarifying the finding within 7 business days.
- Coordinate a public advisory and patch release once a fix is verified.

*Note: Hammerhead is maintained on an open-source basis. While we prioritize security issues urgently, response and resolution times may vary depending on maintainer availability.*

## Development v0.2 execution boundary

Use an ordinary-user account on supported macOS/Linux systems and audit owned or appropriately isolated targets. Native checks use bounded descriptor-relative traversal and a guarded regular-file reader; binary probing shares the verified content handle. Special files are rejected before content reads, supported relative in-root file links remain usable, and absolute/directory links and excluded-target aliases are rejected. Hard links, mount crossings and arbitrary hostile kernel/filesystem behavior are outside a blanket containment guarantee.

This is defense in depth, not an OS sandbox, whole-process memory cap or absolute filesystem cancellation guarantee. Cancellation checks occur between bounded local operations; a stuck kernel/FUSE/network filesystem call can outlast the five-minute context deadline. Logical traversal/read/producer budgets do not bound all RSS or filesystem costs. Termination by SIGKILL/power loss cannot promise a report or exit code.

Git is the separate installed metadata capability and may access external worktree metadata. Its environment/options suppress hooks, fsmonitor, prompting and optional index writes; output/lifetime/process-group cleanup are bounded and tested. Missing Git does not imply a clean Git state. Available failures become partial scans. There is no raw HEAD fallback, and raw Git stderr is never published as a report diagnostic. Native checks do not execute target binaries or build scripts.

Supported filename/header/AWS-shaped observations do not validate credential activity, pairing, tracking, exposure or compromise. Keep fixtures synthetic. Producer secret redaction is distinct from terminal control sanitization and neither promises path privacy. JSON preserves original paths/identities; do not assume terminal-sanitized paths are suitable for matching. Error/short/flush writes cause exit 2; safe stderr is best effort, including broken pipes. See [output](docs/contracts/OUTPUT.md), [scan contracts](docs/contracts/SCAN-RESULT.md) and the [current claims ledger](docs/contracts/CLAIMS.md).
