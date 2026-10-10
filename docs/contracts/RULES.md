# Rule and Variant Inventory

This document freezes the rule variants, rule logic, and explanation design contract.

## Design Contract
- **RuleID**: Uniquely identifies the detection logic (e.g. `FILE-001`).
- **Variant Key**: Identifies the specific outcome inside a single rule, preventing string parsing of the finding Title to determine what happened.
- **Explanation Version**: Future separation between logic and text catalog.

There are exactly 7 rules and 35 variants.

---

## FILE-001: sensitive-file-detection
Matches filenames against a curated list. First match wins per file. Version: 0.2.0 (P1-10 wording only). Contents and exposure are not established by filename matches.

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
Version: 0.2.0 (P1-10 wording only). Size is observed in the audited directory; tracking and history are not evaluated.
- **large-file**: Emitted when a file strictly exceeds the byte threshold. Class: Hygiene. Severity: Low. Confidence: High. Multiple findings can occur. Emits remediation.

## GIT-001: gitignore-hygiene
Version: 0.2.0 (P1-10 wording only). Checks supported textual patterns, not effective Git ignore behavior.
- **missing-file**: Emitted when no `.gitignore` is found in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-env-pattern**: No supported textual pattern for environment files is found in the root `.gitignore`. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-key-pattern**: No supported textual pattern for key files is found in the root `.gitignore`. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.

## GIT-002: git-worktree-health
- **dirty-worktree**: The git index/worktree has uncommitted modifications. Class: Info. Severity: Info. Confidence: High. Emits remediation.
- **detached-head**: The git repository is not currently on a branch. Class: Info. Severity: Info. Confidence: High. Emits remediation.

## PROJ-001: documentation-and-license
Version: 0.2.0 (P1-10 wording only). Recognized filenames do not establish document contents or license adequacy/legal suitability.
- **missing-readme**: No recognized README file in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.
- **missing-license**: No recognized LICENSE file in root. Class: Hygiene. Severity: Low. Confidence: High. Emits remediation.

## PROJ-002: ecosystem-signatures
Class: Info. Severity: Info. Confidence: High. Infers ecosystem context from supported manifest filenames anywhere in the retained inventory; contents and installed runtimes are not verified.
- **go**: Matches `go.mod`. Emits remediation.
- **node**: Matches `package.json`. Emits remediation.
- **python**: Matches `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`. Emits remediation.
- **rust**: Matches `Cargo.toml`. Emits remediation.
- **jvm**: Matches `pom.xml`, `build.gradle`, `build.gradle.kts`. Emits remediation.
- **ruby**: Matches `Gemfile`. Emits remediation.
- **php**: Matches `composer.json`. Emits remediation.
- **container**: Matches `Dockerfile`, `docker-compose.yml`, `compose.yaml`. Emits remediation.
- **terraform**: Matches `*.tf`. Emits remediation.

## SEC-001: secret-content-signatures
Inspects file content. Version: 0.2.0 (P1-10 wording only). Exempts binary files, files > 5 MiB, and the exact supported AWS documentation examples. Credential validity, matching, activity, tracking, exposure, and compromise are not established.
- **private-key-header**: First supported private-key header per file. Class: Security. Severity: High. Confidence: High. Emits remediation. At most one header finding per file.
- **aws-id**: AWS-shaped ID with no supported non-example secret assignment detected in the same file. Class: Security. Severity: Medium. Confidence: Medium. Emits remediation. Multiple possible.
- **aws-id-secret-cooccurrence**: AWS-shaped ID and supported secret assignment found in the same file; pairing is unverified. Class: Security. Severity: Critical. Confidence: High. Emits remediation. Multiple possible.

## P1-10 compatibility

The five versions above change existing finding prose (and GIT-001's textual evidence label), not evaluation. Matching functions, regexes, first-match priority, example exemptions, size/read thresholds, class/severity/confidence, emission counts, locations, redaction and ID inputs are unchanged. GIT-002 remains 0.2.0 from P1-08; PROJ-002 remains 0.1.0. No variant fields, catalog, resolver, renderer, network calls or credential validation were added. See [CLAIMS.md](CLAIMS.md) for the evidence review and remaining documentation work.
