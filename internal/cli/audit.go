package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/talarurus/hammerhead/internal/app"
	"github.com/talarurus/hammerhead/internal/finding"
	"github.com/talarurus/hammerhead/internal/fs"
	"github.com/talarurus/hammerhead/internal/reporter"
)

// parseFailOn converts the --fail-on flag value to a Severity and a boolean indicating if it's disabled.
func parseFailOn(value string) (finding.Severity, bool, error) {
	if value == "none" {
		return 0, true, nil
	}
	sev, err := finding.ParseSeverity(value)
	if err != nil {
		return 0, false, fmt.Errorf("invalid --fail-on value: %w (valid: critical, high, medium, low, info, none)", err)
	}
	return sev, false, nil
}

func newAuditCmd(stdout, stderr io.Writer, audit auditFunc) *cobra.Command {
	var (
		flagOutput      string
		flagFailOn      string
		flagExclude     []string
		flagMaxFileSize string
		flagQuiet       bool
	)

	cmd := &cobra.Command{
		Use:   "audit [path]",
		Short: "Run security checks against a repository",
		Long: `Audit inspects the target directory for security risks including
sensitive files, credential exposure, and repository hygiene issues.

By default, the exit code is non-zero if any HIGH or CRITICAL findings
are detected. Use --fail-on to change this threshold.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			// Validate OutputFormat
			if flagOutput != "terminal" && flagOutput != "json" {
				return &exitError{err: fmt.Errorf("unknown output format: %q (use 'terminal' or 'json')", flagOutput), code: 2}
			}

			// Validate FailOn
			failOnSev, failOnNone, err := parseFailOn(flagFailOn)
			if err != nil {
				return &exitError{err: err, code: 2}
			}

			// Validate MaxFileSize
			var maxFileSize int64
			if flagMaxFileSize != "" {
				size, err := fs.ParseByteSize(flagMaxFileSize)
				if err != nil {
					return &exitError{err: fmt.Errorf("invalid --max-file-size: %w", err), code: 2}
				}
				maxFileSize = size
			}

			// Validate ExcludePatterns
			for _, pat := range flagExclude {
				if _, err := filepath.Match(pat, "test"); err != nil {
					return &exitError{err: fmt.Errorf("invalid exclude pattern %q: %w", pat, err), code: 2}
				}
			}

			req := app.AuditRequest{
				TargetDir:       target,
				FailOn:          failOnSev,
				FailOnNone:      failOnNone,
				ExcludePatterns: flagExclude,
				MaxFileSize:     maxFileSize,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()

			res, runErr := audit(ctx, req)
			if res == nil || res.Result == nil {
				// Map known setup causes without exporting arbitrary service errors,
				// Git stderr, or credential-bearing text from an error implementation.
				message := "audit could not establish a scan scope"
				if errors.Is(runErr, os.ErrNotExist) {
					message = fmt.Sprintf("cannot access %q: no such file or directory", reporter.SanitizeDiagnostic(target))
				} else if errors.Is(runErr, os.ErrPermission) {
					message = fmt.Sprintf("cannot access %q: permission denied", reporter.SanitizeDiagnostic(target))
				}
				return &exitError{err: errors.New(message), code: 2}
			}

			// Select and run the reporter
			var rep reporter.Reporter
			if flagOutput == "json" {
				jsonRep := reporter.NewJSON()
				jsonRep.Writer = stdout
				if Version != "" {
					jsonRep.AppVersion = Version
				}
				jsonRep.FailOn = res.Threshold.Severity
				jsonRep.FailOnNone = res.Threshold.Disabled
				rep = jsonRep
			} else {
				termRep := reporter.NewTerminal()
				termRep.Writer = stdout
				termRep.DiagnosticWriter = stderr
				termRep.Quiet = flagQuiet
				rep = termRep
			}

			if err := rep.Report(res.Result); err != nil {
				// Do not disclose arbitrary writer errors (which can contain secrets).
				return &exitError{err: fmt.Errorf("writing report failed"), code: 2}
			}
			if runErr != nil {
				return &exitError{err: errors.New("audit did not complete"), code: 2}
			}

			// Determine exit code through authoritative application layer
			exitCode := app.ExitCode(res.Result, res.Threshold)

			if exitCode != 0 {
				if exitCode == 1 {
					// normal Exit 1 threshold hit, NO synthetic Error line
					return &exitError{err: nil, code: exitCode}
				}
				err := fmt.Errorf("scan finished with exit code %d", exitCode)
				return &exitError{err: err, code: exitCode}
			}

			return runErr
		},
	}

	cmd.Flags().StringVarP(&flagOutput, "output", "o", "terminal", "Output format: terminal, json")
	cmd.Flags().StringVar(&flagFailOn, "fail-on", "high", "Minimum severity for non-zero exit: critical, high, medium, low, info, none")
	cmd.Flags().StringArrayVarP(&flagExclude, "exclude", "e", nil, "Exclude paths matching pattern (repeatable)")
	cmd.Flags().StringVar(&flagMaxFileSize, "max-file-size", "", "Override large file threshold for FILE-002 (e.g. 50MB, 10MB)")
	cmd.Flags().BoolVarP(&flagQuiet, "quiet", "q", false, "Quiet mode: print compact findings without decorative banners")

	return cmd
}
