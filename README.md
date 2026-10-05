<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/header-white.svg">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/header-navy.svg">
    <img src="docs/assets/header-navy.svg" width="280" alt="hammerhead">
  </picture>
</p>

<p align="center"><strong>Repository security, sharply focused.</strong></p>

<p align="center">A read-only CLI for auditing potentially untrusted repositories for security findings, hygiene issues, and project context.</p>

<p align="center">
  <a href="https://github.com/ammaarrehman/hammerhead/releases/tag/v0.1.0"><img alt="Release v0.1.0" src="https://img.shields.io/badge/release-v0.1.0-19B7C9"></a>
  <a href="go.mod"><img alt="Go 1.26+" src="https://img.shields.io/badge/Go-1.26%2B-0B1F33"></a>
  <a href="LICENSE"><img alt="License Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-0B1F33"></a>
</p>

<p align="center">
  <img src="docs/assets/hammerhead-demo.gif" width="880" alt="Hammerhead v0.1.0 reporting security and hygiene findings, its exit status, and a JSON summary">
</p>
<p align="center"><sub>Real Hammerhead v0.1.0 run on synthetic fixtures. No usable credentials.</sub></p>

## Why Hammerhead

- Audit the current working tree locally, without executing its build scripts or package managers.
- Identify sensitive filenames and supported credential patterns, alongside repository hygiene issues.
- Keep Security, Hygiene, and Info findings separate; only Security findings affect the failure threshold.
- Use readable terminal reports or structured JSON in scripts and automation.

## Installation

Download the archive for your platform from the [v0.1.0 release](https://github.com/ammaarrehman/hammerhead/releases/tag/v0.1.0):

| Platform | Archive |
| --- | --- |
| macOS, Apple Silicon | [darwin_arm64](https://github.com/ammaarrehman/hammerhead/releases/download/v0.1.0/hammerhead_0.1.0_darwin_arm64.tar.gz) |
| macOS, Intel | [darwin_amd64](https://github.com/ammaarrehman/hammerhead/releases/download/v0.1.0/hammerhead_0.1.0_darwin_amd64.tar.gz) |
| Linux, arm64 | [linux_arm64](https://github.com/ammaarrehman/hammerhead/releases/download/v0.1.0/hammerhead_0.1.0_linux_arm64.tar.gz) |
| Linux, amd64 | [linux_amd64](https://github.com/ammaarrehman/hammerhead/releases/download/v0.1.0/hammerhead_0.1.0_linux_amd64.tar.gz) |

Compare the archive's SHA-256 with the release's [checksums.txt](https://github.com/ammaarrehman/hammerhead/releases/download/v0.1.0/checksums.txt), extract it, and put the `hammerhead` executable on your `PATH`. Verify the installed release:

```sh
hammerhead version
```

## Quick start

Audit the current repository:

```sh
hammerhead audit .
```

Write the report as JSON:

```sh
hammerhead audit . --output json > audit.json
```

The default failure threshold is `high`. Exit status `1` means a Security finding met that threshold; Hygiene and Info findings do not trigger it. JSON output uses the same exit behavior as terminal output. Exit status `0` is a threshold result, not a guarantee that a repository is safe or that every file was inspected.

For compact finding lines, use `hammerhead audit . --quiet`. Quiet mode omits the summary; use the regular report or JSON when you need risk and class totals.

## Example findings

This table comes from an actual v0.1.0 run on the separate synthetic demo repository. The PEM placeholder is not a usable key. Matching a key header or filename does not verify a real credential or prove it was committed.

| Check | Class | Severity | Actual finding |
| --- | --- | --- | --- |
| FILE-001 | Security | High | Private key file: `certs/demo.key` |
| SEC-001 | Security | High | Cryptographic private key in file content: `certs/demo.key:1` |
| GIT-001 | Hygiene | Low | Sensitive pattern missing from `.gitignore`: Private keys |
| PROJ-001 | Hygiene | Low | Missing project LICENSE |
| GIT-002 | Info | Info | Uncommitted changes in repository worktree |
| PROJ-002 | Info | Info | Project runtime: Go |

The run produced six findings, security risk `high`, and exit status `1`. The same file can produce more than one finding from different checks.

## JSON and automation

JSON reports use schema `hammerhead/v0.1`. They include repository metadata, a timestamp, version, summary, findings, and any reported check errors. Select the fields you need from the actual report:

```sh
# Use an if block so expected finding exits work even in a shell using set -e.
if hammerhead audit . --output json > audit.json; then
  audit_status=0
else
  audit_status=$?
fi
if [ "$audit_status" -eq 2 ]; then
  printf 'Hammerhead could not complete this invocation.\n' >&2
  exit 2
fi
jq '{schema, version, summary}' audit.json
printf 'Hammerhead exit status: %s\n' "$audit_status"
```

For a script or CI gate, return the saved `audit_status` after processing the report; do not accidentally return only the status of `jq`.

| Exit status | Meaning |
| --- | --- |
| 0 | No Security finding reached the selected threshold |
| 1 | At least one Security finding reached the selected threshold |
| 2 | CLI or operational failure, such as an invalid target or flag value |

`--fail-on` accepts `critical`, `high` (default), `medium`, `low`, `info`, or `none`. Hygiene and Info findings never trigger finding-based failure. `none` disables status 1 from findings, while CLI/operational failures can still return 2.

Check errors can be recorded while other checks continue; they do not automatically force status 2. Review those errors and scan limitations as well as the finding threshold. In v0.1.0, JSON does not expose the walker's skipped-entry list.

Useful audit options:

| Option | Behavior |
| --- | --- |
| `--output json` / `-o json` | Structured JSON; default output is terminal |
| `--quiet` / `-q` | Compact terminal finding lines; omits the summary |
| `--fail-on medium` | Fail on Security findings of medium severity or higher |
| `--exclude certs` / `-e certs` | Exclude a path or matching pattern; repeatable |
| `--max-file-size 10MB` | Override FILE-002's large-file threshold |
| `--help` / `-h` | Actual command help |

`--max-file-size` does not change the security content-read bound in v0.1.0. Run `hammerhead audit --help` for command syntax.

## Checks in v0.1.0

| Check | Class | Purpose |
| --- | --- | --- |
| FILE-001 | Security | Sensitive filenames, including private keys and credential configuration files |
| FILE-002 | Hygiene | Files exceeding the large-file threshold: 50 MiB by default |
| GIT-001 | Hygiene | Missing ignore patterns for supported sensitive file groups |
| GIT-002 | Info | Git worktree state |
| PROJ-001 | Hygiene | Missing README or LICENSE |
| PROJ-002 | Info | Runtime/package-manifest detection |
| SEC-001 | Security | Supported PEM private-key headers and AWS credential patterns in readable text |

## Security model

Hammerhead inspects the target working tree without running its build scripts, package managers, hooks, or binaries. It uses guarded file reads and checks symlink containment relative to the target root. Default traversal limits are depth 50 and 100,000 discovered entries; content reads are bounded at 10 MiB. Common generated/dependency directories and `.git` are excluded.

Git context uses the installed Git executable with explicit options disabling hooks and filesystem-monitor configuration, and a restricted environment. Git metadata is not an outbound credential-validation service. Repository-derived terminal strings are sanitized before display.

These are defense-in-depth measures, not a sandbox or a guarantee that hostile repositories are harmless. Exclusions, unreadable files, size bounds, partial traversal, and check failures can limit coverage. Review findings with that context.

## Limitations

- Scans the current working tree, not Git history.
- Matches supported patterns; it does not validate whether credentials are active or detect every token format.
- Does not provide CVE/dependency database scanning or semantic SAST/data-flow analysis.
- Does not unpack archives; binary and oversized content is outside normal secret-content inspection.
- A successful threshold result is not a clean bill of health.

## Contributing

Use issues for ordinary bugs and focused feature requests, and pull requests for improvements. For vulnerabilities, follow the private route below.

Development requires Go 1.26+; Git is needed for Git-context checks and tests. Existing checks include:

```sh
make test
make vet
```

`make test` runs the Go tests with race detection. Keep fixtures synthetic and do not submit real credentials. Describe changes and how you verified them.

## Security reporting

Follow [SECURITY.md](SECURITY.md) for private reporting and supported versions. Do not report vulnerabilities, active exploits, or actual credential exposures through public issues.

## License

Hammerhead is licensed under [Apache 2.0](LICENSE).
