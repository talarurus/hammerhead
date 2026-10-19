package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/talarurus/hammerhead/internal/app"
	"github.com/talarurus/hammerhead/internal/product"
	"github.com/talarurus/hammerhead/internal/reporter"
)

var (
	Version = product.Version
	Commit  = product.BaseCommit
)

// auditFunc defines the signature for the application audit service.
type auditFunc func(context.Context, app.AuditRequest) (*app.AuditResponse, error)

// Run executes the CLI. It returns an exit code.
// args should not include the program name (e.g. os.Args[1:]).
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithAudit(ctx, args, stdout, stderr, app.Audit)
}

func runWithAudit(ctx context.Context, args []string, stdout, stderr io.Writer, audit auditFunc) int {
	// Cobra's help/usage paths sometimes discard fmt errors. Latch at the
	// stream boundary so those paths still produce operational exit 2.
	out := reporter.NewOutputWriter(stdout)
	diagnostic := reporter.NewOutputWriter(stderr)
	rootCmd := &cobra.Command{
		Use:           "hammerhead-core",
		Short:         "Hammerhead Core: six native file and project checks",
		Long:          "Hammerhead Core inspects native files and project hygiene.\n\n" + product.ScopeNotice + "\nNo full seven-rule coverage or complete repository security is claimed.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.SetArgs(args)
	rootCmd.SetOut(out)
	rootCmd.SetErr(diagnostic)

	rootCmd.AddCommand(newVersionCmd(out))
	rootCmd.AddCommand(newAuditCmd(out, diagnostic, audit))
	// Avoid Cobra's default unknown-help-topic path, which writes to stdout
	// and can call its process-exiting CheckErr instead of returning an error.
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := rootCmd.Find(args)
			if err != nil {
				return err
			}
			if target == nil {
				return fmt.Errorf("unknown help topic")
			}
			target.InitDefaultHelpFlag()
			return target.Help()
		},
	})

	err := rootCmd.ExecuteContext(ctx)
	code := 0
	message := ""
	if err != nil {
		code = 2
		if exitErr, ok := err.(*exitError); ok {
			code = exitErr.ExitCode()
		}
		message = err.Error()
	}
	if out.Flush() != nil {
		code = 2
		// Writer errors are arbitrary caller data, not safe source diagnostics.
		message = "writing output failed"
	}
	if diagnostic.Err() != nil {
		return 2
	}
	if message != "" {
		fmt.Fprintln(diagnostic, reporter.SanitizeDiagnostic("Error: "+message))
	}
	if diagnostic.Flush() != nil {
		return 2
	}
	return code
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
