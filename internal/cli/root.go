package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/ammaarrehman/hammerhead/internal/app"
	"github.com/spf13/cobra"
)

var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

// auditFunc defines the signature for the application audit service.
type auditFunc func(context.Context, app.AuditRequest) (*app.AuditResponse, error)

// Run executes the CLI. It returns an exit code.
// args should not include the program name (e.g. os.Args[1:]).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithAudit(ctx, args, stdout, stderr, app.Audit)
}

func runWithAudit(ctx context.Context, args []string, stdout, stderr io.Writer, audit auditFunc) int {
	rootCmd := &cobra.Command{
		Use:   "hammerhead",
		Short: "Developer-security CLI for repository inspection",
		Long: `Hammerhead inspects software repositories for security risks,
sensitive files, credential exposure, and hygiene issues.

It produces clear, actionable findings with severity levels,
explanations, and remediation guidance.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.SetArgs(args)
	rootCmd.SetOut(stdout)
	rootCmd.SetErr(stderr)

	rootCmd.AddCommand(newVersionCmd(stdout))
	rootCmd.AddCommand(newAuditCmd(stdout, audit))

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		if exitErr, ok := err.(*exitError); ok {
			if exitErr.Error() != "" {
				fmt.Fprintf(stderr, "Error: %v\n", exitErr.err)
			}
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	return 0
}

// exitError wraps an error with an exit code
type exitError struct {
	err  error
	code int
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}
func (e *exitError) ExitCode() int { return e.code }
