# Security Policy

The Hammerhead project takes the security of its code and its users seriously. As a tool designed to inspect potentially untrusted repositories, Hammerhead treats defensive integrity as a primary design requirement.

## Supported Versions

| Version | Supported          |
|:-------:|:------------------:|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest patch release on the current minor branch receives security updates.

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
