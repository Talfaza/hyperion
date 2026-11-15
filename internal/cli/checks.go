package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/colorprofile"
	"github.com/spf13/cobra"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/report"
)

func newChecksCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "checks",
		Short: "List every check with its ISO 27001 control",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list := checks.All()
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(list)
			case "table":
				return report.WriteChecks(colorprofile.NewWriter(cmd.OutOrStdout(), os.Environ()), list)
			}
			return fmt.Errorf("invalid --format %q: want table or json", format)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table or json")
	return cmd
}
