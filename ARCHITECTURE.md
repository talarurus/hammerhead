# Hammerhead Architecture & Technical Design

## 1. System Philosophy & Objectives

Hammerhead is designed as a developer-security auditing CLI. Its primary objective is providing normalized, actionable security insights across software repositories while maintaining strict defensive boundaries when scanning untrusted codebases.

### Architectural Tenets
- **Least Privilege & Read-Only**: Hammerhead inspects repositories passively without intentionally executing untrusted code or altering developer files. Git subprocesses are invoked with repository-controlled execution features disabled.
- **Fail-Safe Traversal**: Hostile directory structures, pathological symlinks, malicious filenames, and oversized files must be isolated at the filesystem layer before reaching checks.
- **Explicit Over Implicit**: Check assembly, configuration, and execution orders are explicitly registered in code rather than discovered via runtime side-effects (`init()` hooks).
- **Normalized Schema**: Findings adhere to a strictly typed, immutable model with explicit classification (`Security`, `Hygiene`, `Info`), severity, confidence, and actionable remediation.
- **Honest Risk Presentation**: Security vulnerabilities are strictly differentiated from repository hygiene. A missing README or an oversized archive never generates a false "High Security Risk" score.

---

## 2. Language Selection: Go

Go (minimum version 1.26+) was selected after evaluating Go, Rust, and Python across ten dimensions:

| Dimension | Go | Rust | Python |
|:---|:---|:---|:---|
| **Binary Distribution** | Static, self-contained binary; cross-compilation trivial via `GOOS`/`GOARCH` | Static binary; cross-compilation requires complex linker toolchains | Requires Python interpreter and virtual environment management |
| **Startup Overhead** | ~5–10 ms | ~3–8 ms | ~80–200 ms |
| **Subprocess Execution** | `os/exec` passes arguments discretely without invoking shell | `std::process::Command` safe but verbose | `subprocess` functional but error-prone |
| **DevSecOps Ecosystem** | Dominant (TruffleHog, Trivy, Syft, Grype, Cosign, Nuclei) | Growing (Ripgrep) but fewer security engines | High research tooling, poor compiled distribution |
| **Untrusted File Safety** | Memory-safe, garbage-collected, standard path libraries | Compile-time memory safety, steep contributor curve | Interpreter vulnerabilities and execution vectors (`setup.py`) |
| **Testing Support** | First-class `testing`, race detector `-race`, built-in fuzzing | Built-in test harness | `pytest` ecosystem, runtime dependency friction |

**Conclusion**: Go provides the optimal balance of execution speed, security toolchain alignment, contributor ergonomics, and reliable single-binary deployment.

---

## 3. Layered Architecture

Hammerhead enforces clear physical and logical boundaries between layers:

```
┌────────────────────────────────────────────────────────┐
│                      CLI Layer                         │
│     (Cobra command definition, CLI flag parsing)       │
├────────────────────────────────────────────────────────┤
│                    Command Layer                       │
│    (Audit orchestrator, flag validation, timeouts)     │
├────────────────────────────────────────────────────────┤
│                    Audit Engine                        │
│ (Coordinates traversal, executes checks, collects data)│
├──────────────────────────┬─────────────────────────────┤
│        SafeWalker        │   Explicit Check Registry   │
│ (Symlink jail, depth,    │ (Deterministic assembly of  │
│  size limits, exclusions)│  active security checks)    │
├──────────────────────────┴─────────────────────────────┤
│                     Check Layer                        │
│    (Implements Check interface, consumes ScanContext)  │
├────────────────────────────────────────────────────────┤
│               Normalized Finding Model                 │
│ (Class: Security/Hygiene/Info, Severity, Remediation)  │
├────────────────────────────────────────────────────────┤
│                    Reporter Layer                      │
│ (Formatters: Terminal with Sanitization, Schema JSON)  │
└────────────────────────────────────────────────────────┘
```

### Component Responsibilities

1. **CLI Layer (`internal/cli`)**:
   - Parses arguments and flags via `github.com/spf13/cobra` (`--fail-on`, `--exclude` / `-e`, `--max-file-size`, `--quiet` / `-q`, `--output` / `-o`).
   - Maps operational failures to exit code `2`.
   - Translates business results into exit codes `0` or `1`.

2. **Command Layer (`internal/cli/audit.go`)**:
   - Sets top-level scan execution contexts with bounded timeouts (default 5 minutes).
   - Validates existence and read permissions of the target path.
   - Parses human-readable size flags (`50MB`, `10KB`) and passes configuration into `engine.ScanConfig`.
   - Instantiates the check registry and invokes the engine.

3. **Audit Engine (`internal/engine`)**:
   - Manages the lifecycle of a scan.
   - Queries Git metadata passively via `internal/git`.
   - Invokes `internal/fs/SafeWalker` to produce an immutable, safe inventory of target files.
   - Configures dynamic thresholds (such as `--max-file-size`) onto relevant checks.
   - Dispatches checks against `check.ScanContext`.
   - Normalizes and sorts findings by severity.

4. **Explicit Check Registry (`internal/engine/registry.go`)**:
   - Centralizes check registration in `DefaultRegistry()`.
   - Rejects duplicate check identifiers at build/init time.
   - Completely avoids Go `init()` registration side-effects, guaranteeing auditability, deterministic testing, and clean lifecycle management.

5. **SafeWalker (`internal/fs/walker.go`)**:
   - Central defensive boundary against untrusted filesystem input.
   - Evaluates user exclusion patterns (`--exclude`) early during directory descent, skipping excluded trees without reading child entries into memory.
   - Ensures checks never directly invoke unbounded filesystem walks or raw `os.Open`.

6. **Check Layer (`internal/check`)**:
   - Implements the `Check` interface (`Meta() Meta` and `Run(ctx, sc) ([]Finding, error)`).
   - Consumes pre-computed `FileInfo` records from `ScanContext`.
   - Reads file data solely through the bounded `sc.ReadFile` handler.

7. **Finding Model (`internal/finding`)**:
   - Canonical representation of security and hygiene observations.
   - Strictly typed `FindingClass` (`ClassSecurity`, `ClassHygiene`, `ClassInfo`).
   - Pure data structures free of OS or network behaviors.

8. **Reporter Layer (`internal/reporter`)**:
   - Consumes `engine.ScanResult` and writes to an `io.Writer`.
   - Terminal reporter sanitizes all repository-controlled strings to prevent terminal injection or header spoofing.
   - Groups output clearly by finding class with dedicated sections for security vs hygiene.
   - Supports quiet mode (`-q`) for clean scripting and automated pipelines.
   - JSON reporter outputs a versioned, machine-readable schema for automation.

---

## 4. Threat Model for Scanning Untrusted Repositories

Auditing untrusted repositories poses specific adversarial threats. The engine mitigates each through architectural controls:

| Threat Vector | Attack Mechanism | Hammerhead Defensive Control |
|:---|:---|:---|
| **Symlink Escapes** | Malicious symlink pointing to `/etc/passwd`, `~/.ssh`, or `/proc/self/environ` | `SafeWalker` evaluates every symlink using `filepath.EvalSymlinks`. Any resolved path residing outside the repository root is skipped and recorded in `SkippedEntries`. |
| **Path Traversal Filenames** | Files named `../../etc/shadow` or containing directory traversal sequences | Relative paths are validated via `containsTraversal()`; entries with `..` components are rejected. |
| **Directory Recursion / Zip-Bombs** | Deeply nested directory trees (`a/b/c/...`) designed to trigger stack or descriptor exhaustion | Enforces `DefaultMaxDepth` (50 levels). Directories exceeding this depth trigger `filepath.SkipDir`. |
| **File Count Exhaustion** | Millions of generated micro-files causing memory exhaustion | Enforces `DefaultMaxFiles` (100,000 files). Traversal halts with a deterministic error when exceeded. |
| **Gigantic / Memory-Exhaustion Files** | Multi-gigabyte sparse or dummy files | `SafeReadFile` strictly bounds read buffers to `DefaultMaxFileSize` (10 MB or `--max-file-size`) using `io.LimitReader`. |
| **Terminal Injection & Output Spoofing** | Filenames or evidence strings with ANSI escape sequences (`\033[...`), carriage returns (`\r`), or newlines (`\n`) intended to spoof false findings or overwrite terminal lines | `internal/reporter/sanitize.go` strips ANSI escape sequences, replaces control characters/carriage returns with space, and collapses multi-line spoofing attempts before rendering to terminals. |
| **Control Character Filenames** | Filenames containing null bytes or dangerous control codes to corrupt filesystem APIs | `checkFilename()` sanitizes names; entries with null bytes (`\x00`) or Unicode control characters are rejected before reporting. |
| **Vendor / Dependency Bloat** | Hundreds of thousands of vendor files in `node_modules`, `.venv`, or `.git` creating noise and slowdowns | Default skip list for high-noise metadata/vendor directories (`.git`, `node_modules`, `vendor`, `.venv`, `__pycache__`, etc.), augmented by user `--exclude` patterns. |
| **Binary File False Positives** | Matching text patterns across compiled binaries or core dumps | `IsBinaryFile` examines the initial 512 bytes via `http.DetectContentType` to classify MIME streams. |
| **Subprocess Injection** | Repository contents interpolated into shell commands | `internal/git` executes binaries (`git`) directly with discrete arguments via `exec.Command` and explicitly disables repository-controlled execution features (`core.fsmonitor`, hooks). Shell interpreters (`sh -c`) are strictly forbidden. |

---

## 5. Normalized Finding Model

```go
type FindingClass string

const (
    ClassSecurity FindingClass = "security" // Potential security risks from supported content or filename patterns
    ClassHygiene  FindingClass = "hygiene"  // Best practices, gitignore coverage, README/LICENSE, large files
    ClassInfo     FindingClass = "info"     // Project ecosystem hints, dirty worktree or detached HEAD observations
)

type Finding struct {
    ID          string       `json:"id"`
    RuleID      string       `json:"rule_id"`
    Class       FindingClass `json:"class"`
    Category    Category     `json:"category"`
    Severity    Severity     `json:"severity"`
    Confidence  Confidence   `json:"confidence"`
    Title       string       `json:"title"`
    Description string       `json:"description"`
    Remediation string       `json:"remediation"`
    Path        string       `json:"path,omitempty"`
    Line        int          `json:"line,omitempty"`
    Evidence    string       `json:"evidence,omitempty"`
    Source      string       `json:"source"`
    CheckVer    string       `json:"check_ver"`
}
```

### Design Rationales
- **Finding Classification (`Class`)**:
  - `ClassSecurity`: Potential security risks from private-key headers, AWS-shaped ID/secret co-occurrence, and sensitive filename patterns. These observations do not establish credential validity, matching, activity, commitment, exposure, or compromise. Only findings in this class influence the overall `Security risk` level and trigger CI failure thresholds (`--fail-on`).
  - `ClassHygiene`: Repository hygiene and governance (missing README/LICENSE, missing `.gitignore` rules, large files). Important for developer quality, but never flagged as a security vulnerability.
  - `ClassInfo`: Informational project metadata (detected runtimes, worktree modification status).
- **Deterministic ID Generation**: `GenerateID(ruleID, path)` hashes `ruleID:path` with SHA-256 (truncated to 8 hex characters). The same inputs produce the same short ID; collisions are possible and findings are not deduplicated by ID.
- **Severity vs Confidence Separation**:
  - `Severity` indicates potential business impact (`Critical`, `High`, `Medium`, `Low`, `Info`).
  - `Confidence` describes certainty in the supported observation or heuristic (`High`, `Medium`, `Low`), not credential verification or exposure.
- **Complete Secret Redaction**: Evidence fields never contain raw credentials. Secret keys are completely redacted (`AKIA**************** [SECRET KEY REDACTED]`).
- **Mandatory Remediation**: Every check must define a concrete, step-by-step remediation path.

---

## 6. Exit-Code Semantics

Hammerhead follows standard Unix CLI exit code conventions with threshold awareness:

```
Exit 0: Audit completed; max(ClassSecurity.Severity) < FailOn
Exit 1: Audit completed; max(ClassSecurity.Severity) >= FailOn
Exit 2: Internal failure, invalid arguments, or fatal I/O error
```

### CI/CD Threshold Isolation
The threshold flag (`--fail-on`) allows CI/CD systems to enforce strict or relaxed gating policies without changing CLI commands. Because `--fail-on` only triggers on `ClassSecurity` findings, non-security hygiene observations (such as a missing README or a 55MB dataset) will never inadvertently break production builds.

---

## 7. Future External Tool Integration Model

Future milestones (V0.2+) will orchestrate mature third-party scanners (TruffleHog, Trivy, OSV):

```go
type ExternalScanner interface {
    Name() string
    Available(ctx context.Context) (bool, string)
    Scan(ctx context.Context, sc *check.ScanContext) ([]finding.Finding, error)
}
```

### Integration Constraints
1. **Subprocess Isolation**: External binaries must be invoked with isolated environments (`cmd.Env`), bounded timeouts, and discrete argument arrays.
2. **Normalized Translation**: The external tool's native output (JSON or SARIF) is parsed and mapped directly into the canonical `finding.Finding` model with `Source` set to the external engine name.
3. **Graceful Fallback**: If an external engine is not installed, Hammerhead logs an informational skip or falls back to native heuristic checks, never failing the audit catastrophically.
