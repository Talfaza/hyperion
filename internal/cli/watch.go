package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
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
	var paths []string
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Report changes to watched files live, with who made them (experimental, eBPF)",
		Long: "Stream changes to watched files as they happen, with who made them:\n" +
			"writes, creations, renames, deletions, chmod, chown and truncation.\n" +
			"Experimental. Uses observe-only eBPF programs; needs root and a kernel\n" +
			"with BTF (5.10+; chmod/chown/truncate need 5.12+).",
		Example: "  sudo hyperion-trace watch\n" +
			"  sudo hyperion-trace watch --paths /etc,/opt/app/config\n" +
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
			warn := func(msg string) { fmt.Fprintln(os.Stderr, "warning: "+msg) }
			shown := paths
			if len(shown) == 0 {
				shown = watch.DefaultPaths
			}
			// "ready" goes to stderr in every format, once the hooks are
			// attached, so scripts know when changes start being recorded.
			ready := func() {
				fmt.Fprintf(os.Stderr, "ready: watching %s (Ctrl+C to stop)\n", strings.Join(shown, ", "))
			}
			st, err := watch.Run(ctx, watch.Options{Paths: paths, Warn: warn, Ready: ready}, func(e watch.Event) {
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
			if st.Dropped > 0 {
				warn(fmt.Sprintf("%d events dropped (ring buffer full)", st.Dropped))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table or json (one object per line)")
	cmd.Flags().DurationVar(&duration, "duration", 0, "stop after this long (default: until Ctrl+C)")
	cmd.Flags().StringSliceVar(&paths, "paths", nil, "directories to watch (default: "+strings.Join(watch.DefaultPaths, ",")+")")
	return cmd
}

var (
	watchTime = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	watchOp   = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	watchPath = lipgloss.NewStyle().Bold(true)
)

func formatEvent(e watch.Event, names *userNames) string {
	who := names.name(e.EUID)
	if e.LoginUID != nil && *e.LoginUID != e.EUID {
		who = names.name(*e.LoginUID) + " → " + who
	}
	// Everything below comes from the watched system: sanitize it.
	what := watchPath.Render(report.Sanitize(e.Path))
	switch {
	case e.Op == watch.OpRename && e.From != "":
		what = report.Sanitize(e.From) + " → " + what
	case e.Op == watch.OpRename:
		what = "(from outside watched paths) → " + what
	case e.Op == watch.OpChmod && e.Mode != nil:
		what += fmt.Sprintf(" mode %04o", *e.Mode)
	case e.Op == watch.OpChown:
		owner := "-"
		if e.NewOwner != nil {
			owner = names.name(*e.NewOwner)
		}
		group := "-"
		if e.NewGroup != nil {
			group = strconv.FormatUint(uint64(*e.NewGroup), 10)
		}
		what += " owner " + owner + ":" + group
	}
	process := report.Sanitize(e.Comm)
	if e.Cmdline != "" {
		process = report.Sanitize(e.Cmdline)
		if len(process) > 80 {
			process = process[:79] + "…"
		}
	}
	return fmt.Sprintf("%s %-9s %s  %s",
		watchTime.Render(e.Time.Format("15:04:05.000")),
		watchOp.Render(string(e.Op)),
		what,
		watchTime.Render(fmt.Sprintf("by %s · %s (pid %d, parent %d)", who, process, e.PID, e.PPID)))
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
