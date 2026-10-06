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
