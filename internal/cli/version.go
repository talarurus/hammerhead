package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"github.com/talarurus/hammerhead/internal/product"
	"github.com/talarurus/hammerhead/internal/reporter"
)

func newVersionCmd(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Hammerhead Core version and scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(stdout, "Hammerhead Core version %s (source base: %s)\n", reporter.SanitizeOneLine(Version), reporter.SanitizeOneLine(Commit))
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(stdout, product.ScopeNotice)
			return err
		},
	}
}
