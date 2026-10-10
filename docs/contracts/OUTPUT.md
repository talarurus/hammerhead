# Output and diagnostic contract (P1-11 / G11)

Report completion is separate from scan completion. A write, nil-error short
write, or buffered flush failure makes the invocation exit 2, overriding a
finding-threshold exit of 0 or 1. The stored scan status and findings do not
change. After the first stream error, its writer stops calling the destination.
The CLI may still try one safe operational message on stderr. If stderr also
fails, exit 2 remains the outcome; delivery of a message cannot be promised.
Caller-supplied writers exposing `Flush() error` are finalized and checked.
No internal output buffering is introduced.

Terminal reports show status and coverage before an empty-findings message.
Unknown coverage remains unknown. Quiet mode writes only compact finding lines
to stdout and sends status, coverage and typed diagnostics to the injected
stderr writer, including zero-findings incomplete runs. JSON stdout contains
exactly one `hammerhead/v0.2` document when writing succeeds. Invocation errors
use stderr; a failed stdout write cannot promise a complete JSON document.

Terminal presentation removes ANSI/CSI, OSC and other terminal control strings,
including unterminated strings and C1 forms, as well as Unicode format/bidi
controls. Untrusted one-line text cannot inject CR/LF or other line separators.
Reviewed description/remediation prose may retain whitespace before wrapping.
General terminal text is bounded to 16 KiB before parsing; complete diagnostic
lines are bounded to 2 KiB and terminal diagnostic samples to 200. Additional
samples are identified as omitted. Presentation limits never crop stored
identities, alter matching, or modify JSON. Sanitization is not secret redaction
or a promise of path privacy. Existing producer redaction and safe typed
messages remain separate requirements. Arbitrary service and writer error text
is not printed; known setup causes and generic operational messages are used.

On Unix, Go 1.26.9's `os.File.Write` calls `epipecheck`: EPIPE on stdout/stderr
normally raises SIGPIPE and can terminate the process with a signal instead of
exit 2. The executable ignores SIGPIPE before calling the CLI, allowing EPIPE
to reach the checked writer and operational exit resolver. This is a deliberate
process-wide executable policy, not a signal-handler change in the embeddable
`cli.Run` function. Hosts embedding the CLI must supply an equivalent signal
policy if using real Unix standard descriptors and requiring exit 2.

Real closed-pipe subprocess tests cover audit, JSON, quiet, help, version and
stderr, including both output streams broken. Parent watchdogs bound child
lifetime and close inherited pipe endpoints. These tests validate macOS/Linux
runtime behavior, not arbitrary host signal handlers. SIGKILL, power loss,
uninterruptible I/O, and a writer that blocks without returning cannot guarantee
report delivery or exit 2.
