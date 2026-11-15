// Package cli wires the hyperion-trace commands together.
package cli

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/Talfaza/hyperion/internal/platform"
)

// newHost is swapped out by tests to scan fixture directories.
var newHost = platform.NewLocalHost

// ExitError carries a specific process exit code (e.g. 2 for --fail-under).
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

func newRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "hyperion-trace",
		Short: "Linux security posture auditing for ISO/IEC 27001",
		Long: "Hyperion Trace audits Linux hosts against the Hyperion hardening baseline " +
			"(ISO/IEC 27001:2022 Annex A). It only reads system state: it never changes " +
			"configuration and never sends data over the network.",
	}
	root.AddCommand(newScanCmd(version), newChecksCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, version string) int {
	err := fang.Execute(ctx, newRootCmd(version),
		fang.WithVersion(version),
		fang.WithNotifySignal(os.Interrupt, syscall.SIGTERM),
	)
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return 1
}
