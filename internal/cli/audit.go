package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ammaarrehman/hammerhead/internal/engine"
	"github.com/ammaarrehman/hammerhead/internal/finding"
	"github.com/ammaarrehman/hammerhead/internal/fs"
	"github.com/ammaarrehman/hammerhead/internal/reporter"
)

var auditCmd = &cobra.Command{
	Use:   "audit [path]",
	Short: "Run security checks against a repository",
	Long: `Audit inspects the target directory for security risks including
sensitive files, credential exposure, and repository hygiene issues.

By default, the exit code is non-zero if any HIGH or CRITICAL findings
are detected. Use --fail-on to change this threshold.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runAudit,
}

var (
	flagOutput      string
	flagFailOn      string
	flagExclude     []string
	flagMaxFileSize string
	flagQuiet       bool
)

func init() {
	auditCmd.Flags().StringVarP(&flagOutput, "output", "o", "terminal", "Output format: terminal, json")
	auditCmd.Flags().StringVar(&flagFailOn, "fail-on", "high", "Minimum severity for non-zero exit: critical, high, medium, low, info, none")
	auditCmd.Flags().StringArrayVarP(&flagExclude, "exclude", "e", nil, "Exclude paths matching pattern (repeatable)")
	auditCmd.Flags().StringVar(&flagMaxFileSize, "max-file-size", "", "Override large file threshold for FILE-002 (e.g. 50MB, 10MB)")
	auditCmd.Flags().BoolVarP(&flagQuiet, "quiet", "q", false, "Quiet mode: print compact findings without decorative banners")
	rootCmd.AddCommand(auditCmd)
}

func runAudit(cmd *cobra.Command, args []string) error {
	// Determine target directory.
	target := "."
	if len(args) > 0 {
		target = args[0]
	}

	// Validate the target exists and is a directory.
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("cannot access %q: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", target)
	}

	// Parse the --fail-on threshold.
	failOn, err := parseFailOn(flagFailOn)
	if err != nil {
		return err
	}

	// Parse optional --max-file-size override.
	var maxFileSize int64
	if flagMaxFileSize != "" {
		parsedSize, err := fs.ParseByteSize(flagMaxFileSize)
		if err != nil {
			return fmt.Errorf("invalid --max-file-size: %w", err)
		}
		maxFileSize = parsedSize
	}

	// Set up scan with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Build the engine with the explicit default registry.
	registry := engine.DefaultRegistry()
	eng := engine.New(registry)

	config := &engine.ScanConfig{
		FailOn:             failOn,
		ExcludePatterns:    flagExclude,
		LargeFileThreshold: maxFileSize,
	}

	// Run the scan.
	result, runErr := eng.Scan(ctx, target, config)
	if result == nil {
		return fmt.Errorf("scan failed: %w", runErr)
	}

	// Select and run the reporter.
	var rep reporter.Reporter
	switch flagOutput {
	case "terminal", "":
		termRep := reporter.NewTerminal()
		termRep.Quiet = flagQuiet
		rep = termRep
	case "json":
		jsonRep := reporter.NewJSON()
		if Version != "" {
			jsonRep.AppVersion = Version
		}
		rep = jsonRep
	default:
		return fmt.Errorf("unknown output format: %q (use 'terminal' or 'json')", flagOutput)
	}

	if err := rep.Report(result); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}

	// Exit with appropriate code based on threshold.
	exitCode := result.ExitCode(failOn)
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	// For testability, return the err if the program doesn't exit.
	return runErr
}

// parseFailOn converts the --fail-on flag value to a Severity.
// The special value "none" means never fail on findings.
func parseFailOn(value string) (finding.Severity, error) {
	if value == "none" {
		// Set threshold above maximum severity — nothing will trigger failure.
		return finding.SeverityCritical + 1, nil
	}
	sev, err := finding.ParseSeverity(value)
	if err != nil {
		return 0, fmt.Errorf("invalid --fail-on value: %w (valid: critical, high, medium, low, info, none)", err)
	}
	return sev, nil
}
