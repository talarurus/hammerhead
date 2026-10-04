// Package cli defines the Hammerhead command-line interface.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build-time variables injected via ldflags.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

// rootCmd is the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "hammerhead",
	Short: "Developer-security CLI for repository inspection",
	Long: `Hammerhead inspects software repositories for security risks,
sensitive files, credential exposure, and hygiene issues.

It produces clear, actionable findings with severity levels,
explanations, and remediation guidance.`,
	SilenceUsage:  true, // Don't print usage on errors.
	SilenceErrors: true, // We handle error display ourselves.
}

// Execute runs the root command. This is the main entry point.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
