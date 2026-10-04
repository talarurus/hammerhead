# Contributing to Hammerhead

Thank you for your interest in contributing to Hammerhead. We welcome contributions that improve security detection, expand coverage, harden runtime defenses, and enhance developer experience.

## Prerequisites

- **Go**: Version 1.26 or higher
- **Git**
- **Make** (optional, for convenience targets)

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/ammaarrehman/hammerhead.git
   cd hammerhead
   ```

2. Build the binary:
   ```bash
   make build
   ```

3. Run the test suite:
   ```bash
   make test
   ```

4. Run all quality checks (formatting, vet, and race-detector tests):
   ```bash
   make check
   ```

## Code Standards & Formatting

- All Go code must be formatted using standard `gofmt`:
  ```bash
  make fmt
  ```
- Code must pass `go vet ./...` without warnings.
- All tests must pass cleanly under the race detector: `go test -race -count=1 ./...`.

## Architecture & Rule Development

Hammerhead is designed to be deterministic, safe, and maintainable.

### The Check Interface

All security and hygiene checks implement the `check.Check` interface in `internal/check/check.go`:

```go
type Check interface {
    Meta() Meta
    Run(ctx context.Context, sc *ScanContext) ([]finding.Finding, error)
}
```

### Explicit Registration (No `init()`)

- **Strictly No `init()` Registration**: Checks must **never** register themselves automatically via package `init()` functions. Automatic registration introduces hidden dependencies, non-deterministic ordering, and side-effects during testing.
- All checks must be explicitly instantiated and registered in `internal/check/registry.go` within `NewRegistryWithDefaults()`.

### Testing Requirements for New Checks

Any PR introducing or modifying a check must include:
1. **Positive Tests**: Verify detection correctly triggers on targeted patterns, file structures, or credentials.
2. **Negative Tests**: Verify benign patterns, valid public files, and clean repositories do **not** trigger false positives.
3. **Edge-Case Tests**: Verify robust handling of empty files, binary content, maximum size limits, and malformed inputs without crashing.

### Security-Sensitive Coding Expectations

Hammerhead audits potentially untrusted and hostile codebases. When writing code:

- **No Shell Invocations**: Subprocesses must never be launched via shell wrappers (`sh -c`, `bash -c`, or cmd string interpolation). Subprocesses must invoke explicit binary paths with separate argument slices.
- **No Secret Evidence Leakage**: Findings must never include raw secrets, plaintext tokens, or complete private keys in the `Evidence` field. Always redact, mask, or display only safe prefixes/character counts.
- **Respect Filesystem Boundaries**: Never read files directly using unvalidated paths. Use `sc.ReadFile` or `SafeWalker.SafeReadFile`, which enforce root-jail boundaries and file size limits.
- **Terminal Sanitization**: Any string originating from repository files, paths, or Git metadata must pass through terminal sanitization before display to prevent ANSI/control-character injection.

## Documentation & Commits

- If a change introduces a new check or CLI flag, update `README.md` and `ARCHITECTURE.md` accordingly.
- Keep commits focused and descriptive using conventional commit formatting (e.g., `feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
