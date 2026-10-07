package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

func newVersionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Hammerhead version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(stdout, "hammerhead version %s (commit: %s)\n", Version, Commit)
		},
	}
}
