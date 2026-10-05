# Rule and Variant Inventory

This document freezes the rule variants, rule logic, and explanation design contract.

## Design Contract
- **RuleID**: Uniquely identifies the detection logic (e.g. `FILE-001`).
- **Variant Key**: Identifies the specific outcome inside a single rule, preventing string parsing of the finding Title to determine what happened.
- **Explanation Version**: Future separation between logic and text catalog.

There are exactly 7 rules and 35 variants.

---

## FILE-001: sensitive-file-detection
Matches filenames against a curated list. First match wins per file. Version: 0.1.0.

- **ssh-rsa**: Matches `id_rsa`. Class: Security. Severity: High. Confidence: High. Emits remediation.
- **ssh-dsa**: Matches `id_dsa`. Class: Security. Severity: High. Confidence: High. Emits remediation.
- **ssh-ecdsa**: Matches `id_ecdsa`. Class: Security. Severity: High. Confidence: High. Emits remediation.
- **ssh-ed25519**: Matches `id_ed25519`. Class: Security. Severity: High. Confidence: High. Emits remediation.
- **pem-file**: Matches `*.pem`. Class: Security. Severity: High. Confidence: Medium. Emits remediation.
- **key-file**: Matches `*.key`. Class: Security. Severity: High. Confidence: Medium. Emits remediation.
- **pkcs12-file**: Matches `*.p12`, `*.pfx`. Class: Security. Severity: High. Confidence: High. Emits remediation.
- **java-keystore-file**: Matches `*.jks`, `*.keystore`. Class: Security. Severity: High. Confidence: Medium. Emits remediation.
- **env-file**: Matches `.env`, `.env.*` (but exempts `*.example`, `*.template`, `*.sample`, `*.dist`). Class: Security. Severity: Medium. Confidence: High. Emits remediation.
- **htpasswd-file**: Matches `.htpasswd`. Class: Security. Severity: Medium. Confidence: High. Emits remediation.
- **netrc-file**: Matches `.netrc`, `_netrc`. Class: Security. Severity: Medium. Confidence: High. Emits remediation.
- **pgpass-file**: Matches `.pgpass`. Class: Security. Severity: Medium. Confidence: High. Emits remediation.
- **package-manager-config**: Matches `.npmrc`, `.pypirc`. Class: Security. Severity: Medium. Confidence: Medium. Emits remediation.
- **credentials-name**: Name contains `credentials` (exempts code files). Class: Security. Severity: Medium. Confidence: Medium. Emits remediation.
- **secret-name**: Name contains `secret` (exempts code files). Class: Security. Severity: Medium. Confidence: Low. Emits remediation.

## FILE-002: large-file-detection
- **large-file**: Emitted when a file strictly exceeds the byte threshold. Class: Hygiene. Severity: Low. Confidence: High. Multiple findings can occur. Emits remediation.

## GIT-001: gitignore-best-practices
- **missing-file**: Emitted when no `.gitignore` is found in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-env-pattern**: `.gitignore` is missing a pattern ignoring environment files. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-key-pattern**: `.gitignore` is missing a pattern ignoring key files. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.

## GIT-002: git-worktree-health
- **dirty-worktree**: The git index/worktree has uncommitted modifications. Class: Info. Severity: Info. Confidence: High. Emits remediation.
- **detached-head**: The git repository is not currently on a branch. Class: Info. Severity: Info. Confidence: High. Emits remediation.

## PROJ-001: project-hygiene
- **missing-readme**: No recognized README file in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-license**: No recognized LICENSE file in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.

## PROJ-002: ecosystem-signatures
Class: Info. Severity: Info. Confidence: High. Detects frameworks/tools based on root lockfiles/configs.
- **go**: Matches `go.mod`. Emits remediation.
- **node**: Matches `package.json`, `yarn.lock`, etc. Emits remediation.
- **python**: Matches `requirements.txt`, `Pipfile`, `pyproject.toml`. Emits remediation.
- **rust**: Matches `Cargo.toml`. Emits remediation.
- **jvm**: Matches `pom.xml`, `build.gradle`. Emits remediation.
- **ruby**: Matches `Gemfile`. Emits remediation.
- **php**: Matches `composer.json`. Emits remediation.
- **container**: Matches `Dockerfile`, `docker-compose.yml`. Emits remediation.
- **terraform**: Matches `*.tf`. Emits remediation.

## SEC-001: secret-content-signatures
Inspects file content. Version: 0.1.0. Exempts binary files, files > 5MB, and AWS documentation examples.
- **private-key-header**: PEM-encoded private key header. Class: Security. Severity: High. Confidence: High. Emits remediation. Multiple possible.
- **aws-id**: Access Key ID identified without secret. Class: Security. Severity: Medium. Confidence: Medium. Emits remediation. Multiple possible.
- **aws-id-secret-cooccurrence**: Access Key ID and Secret Access Key assignment found in same file. Class: Security. Severity: Critical. Confidence: High. Emits remediation. Multiple possible.
