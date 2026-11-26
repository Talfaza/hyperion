package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/spf13/cobra"

	"charm.land/lipgloss/v2"

	"github.com/Talfaza/hyperion/internal/report"
	"github.com/Talfaza/hyperion/internal/watch"
)

func newWatchCmd() *cobra.Command {
	var format string
	var duration time.Duration
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Report files under /etc opened for writing, live (experimental, eBPF)",
		Long: "Stream changes to watched files as they happen, with who made them.\n" +
			"Experimental (milestone 0): reports files under /etc opened for writing.\n" +
			"Uses an observe-only eBPF program; needs root and a kernel with BTF (5.10+).",
		Example: "  sudo hyperion-trace watch\n" +
			"  sudo hyperion-trace watch --format json --duration 30s",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if format != "table" && format != "json" {
				return fmt.Errorf("invalid --format %q: want table or json", format)
			}
			if duration < 0 {
				return fmt.Errorf("invalid --duration %s", duration)
			}
			if os.Geteuid() != 0 {
				return watch.ErrNotPrivileged
			}
			ctx := cmd.Context()
			if duration > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, duration)
				defer cancel()
			}
			out := cmd.OutOrStdout()
			enc := json.NewEncoder(out)
			w := colorprofile.NewWriter(out, os.Environ())
			names := newUserNames()
			if format == "table" {
				fmt.Fprintln(os.Stderr, "watching /etc for writes (Ctrl+C to stop)")
			}
			dropped, err := watch.Run(ctx, func(e watch.Event) {
				if format == "json" {
					_ = enc.Encode(e)
					return
				}
				fmt.Fprintln(w, formatEvent(e, names))
			})
			if errors.Is(err, watch.ErrNotPrivileged) {
				return err
			}
			if err != nil {
				return err
			}
			if dropped > 0 {
				fmt.Fprintf(os.Stderr, "warning: %d events dropped (ring buffer full)\n", dropped)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table or json (one object per line)")
	cmd.Flags().DurationVar(&duration, "duration", 0, "stop after this long (default: until Ctrl+C)")
	return cmd
}

var (
	watchTime = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	watchOp   = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	watchPath = lipgloss.NewStyle().Bold(true)
)

func formatEvent(e watch.Event, names *userNames) string {
	who := names.name(e.UID)
	if e.LoginUID != nil && *e.LoginUID != e.UID {
		who = names.name(*e.LoginUID) + " → " + who
	}
	// Path and comm come from the watched system: sanitize before printing.
	return fmt.Sprintf("%s %s %s  %s",
		watchTime.Render(e.Time.Format("15:04:05.000")),
		watchOp.Render(string(e.Op)),
		watchPath.Render(report.Sanitize(e.Path)),
		watchTime.Render(fmt.Sprintf("by %s · %s (pid %d)", who, report.Sanitize(e.Comm), e.PID)))
}

// userNames caches uid → name lookups (from /etc/passwd via os/user).
type userNames struct{ cache map[uint32]string }

func newUserNames() *userNames { return &userNames{cache: map[uint32]string{}} }

func (u *userNames) name(uid uint32) string {
	if n, ok := u.cache[uid]; ok {
		return n
	}
	n := strconv.FormatUint(uint64(uid), 10)
	if usr, err := user.LookupId(n); err == nil {
		n = report.Sanitize(usr.Username)
	}
	u.cache[uid] = n
	return n
}
