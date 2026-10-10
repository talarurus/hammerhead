package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/talarurus/hammerhead/internal/reporter"
)

func newVersionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Hammerhead version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(stdout, "hammerhead version %s (commit: %s)\n", reporter.SanitizeOneLine(Version), reporter.SanitizeOneLine(Commit))
			return err
		},
	}
}
