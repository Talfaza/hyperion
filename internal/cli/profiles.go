package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/colorprofile"
	"github.com/spf13/cobra"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/profiles"
	"github.com/Talfaza/hyperion/internal/report"
)

func newProfilesCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List scan profiles and exactly what each one changes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := profiles.Validate(checks.All()); err != nil {
				return err
			}
			var list []profiles.Profile
			for _, n := range profiles.Names() {
				p, _ := profiles.Lookup(n)
				list = append(list, p)
			}
			switch format {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(list)
			case "table":
				return report.WriteProfiles(colorprofile.NewWriter(cmd.OutOrStdout(), os.Environ()), list)
			}
			return fmt.Errorf("invalid --format %q: want table or json", format)
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table or json")
	return cmd
}
