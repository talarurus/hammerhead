# Migrating to Hammerhead v0.2

Hammerhead v0.2 is proposed to introduce an intentional break in schema and exit behavior to correctly distinguish incomplete or failed scans from successful clean scans. These changes are currently proposed and not yet implemented.

## What Will Change?

1. **Exit Codes**: In v0.1, operational errors or unreadable files did not reliably yield a non-zero exit code if no secrets were found. In the proposed v0.2, any incomplete scan (`partial`, `failed`, `cancelled`), or an invalid request, will exit with code `2`. Finding-based exits (e.g., critical secret found) continue to exit with code `1`.
2. **JSON Schema**: The JSON output schema will be upgraded to `hammerhead/v0.2`. It will include detailed `status`, structured `threshold`, nested `coverage`, and typed `diagnostics` fields. A legacy v0.1 serializer will NOT be provided because no IN-REPOSITORY or CI consumer was found requiring it, though external consumers may exist.

## What Users Relying on v0.1 Behavior Should Do

If your automated scripts or pipelines depend strictly on the `v0.1` JSON format or its legacy exit code behaviors:

- Pin your installation to the `v0.1.0` tag. The legacy release and its fixtures remain intact and preserved.
- When you upgrade to `v0.2`, update your scripts to handle the new nested JSON schema structure and the new explicit exit code `2` for operational failures.
- Do not expect `--fail-on none` to suppress exit code `2`. It only suppresses finding-based exits (code `1`), never operational failures.
- Setup failures may exit with code `2` without a complete scan report. However, meaningful partial results will be retained and rendered.

## Git context in v0.2-dev

C11 removes the raw `.git/HEAD` fallback. When Git is missing, native checks
continue, GIT-002 coverage is `unavailable`, and a bounded `git_unavailable`
diagnostic explains that Git health was not evaluated. This alone does not
make the audit partial. Ordinary non-Git directories and audited Git
subdirectories have `not_applicable` Git health coverage. Available Git
operations that time out, exceed output limits, return malformed output, or
fail unexpectedly make the audit `partial` (exit 2, including `--fail-on none`).

The engine collects detection, branch, and root-only worktree status once;
GIT-002 consumes that snapshot without filesystem or subprocess access. Normal,
unborn, and detached branch states are distinguished without reading HEAD.
Porcelain v1 NUL records count each rename/copy once and preserve filenames with
newlines or control characters; old line-based counts could overcount them.
Submodule status remains ignored, and `GIT_OPTIONAL_LOCKS=0` suppresses optional
index refresh writes.

Git worktrees may reference metadata outside the audited directory. That is an
explicit exception for the existing bounded Git executable, separate from the
rooted native-content boundary. It does not give checks access to those files.

An exact C-locale non-repository diagnostic is accepted only when a bounded
metadata existence probe finds no `.git` marker in the target or its ancestors.
A marker, an inaccessible probe, or exceeding 256 ancestor steps leaves Git
state ambiguous and makes the audit partial. The probe uses only `Lstat`; it
reads no Git file content and never supplies root, branch, or status data.
