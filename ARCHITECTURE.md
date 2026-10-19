# Hammerhead Core architecture

This is an isolated source snapshot based on protected commit `4fa1018b13ed4b8b6af194a326105e098dc8118f`, not a change to the full Hammerhead branch. The Go module identity remains `github.com/talarurus/hammerhead` to reuse internal packages. The only command is `cmd/hammerhead-core`.

`cli.Run` validates options and invokes `app.Audit`; the application assembles exactly six native checks. The engine opens one root authority, traverses safely, builds the guarded reader from that handle, runs the checks, and collects bounded findings and coverage. The existing reporter handles JSON, terminal, quiet and checked output failures. The command converts SIGINT/SIGTERM into cooperative cancellation, subject to the existing five-minute scan cap.

The Core boundary is structural: `internal/git`, the Git health check and Git snapshot carrier are absent. The engine's automatic Git collection, Git binding observer call and Git-only policy limits are removed. No runtime option can add them back. Checks receive no Git snapshot or subprocess capability. GIT-001 uses only the ordinary rooted reader and traversal presence facts.

All 15 production files in `internal/fs` match the protected base byte-for-byte. This includes the descriptor-relative walker/resolver/reader and unused pathname observer support. The observer has no caller in the Core production graph and its entrypoints are absent from the linked executable. Keeping that unused filesystem support avoids altering the reviewed native implementation; it does not collect metadata or start a process. Source/import and binary/dependency evidence are in `release/evidence`.

Core scope is a fixed contract in `internal/product`. JSON explicitly separates six included checks from `scope.not_evaluated`, where GIT-002 is `not_evaluated`; GIT-002 is never represented as passed or completed. Overall completion and exit resolution retain native failure precedence. Collection/read/traversal budgets retain their original values; only the removed Git budgets disappear.
