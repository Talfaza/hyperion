package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/exceptions"
	"github.com/Talfaza/hyperion/internal/profiles"
	"github.com/Talfaza/hyperion/internal/report"
)

// now is swapped out by tests to check exception expiry.
var now = time.Now

type scanOptions struct {
	format      string
	failUnder   int
	skip        []string
	only        []string
	minSeverity string
	failedOnly  bool
	timeout     time.Duration

	exceptionsPath     string
	exceptionsExplicit bool
	noExceptions       bool

	profile string
}

func newScanCmd(version string) *cobra.Command {
	var o scanOptions
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Audit this host against the hardening baseline",
		Long: "Run every baseline check against this host and print a 0-100 posture score.\n" +
			"Run as root for a complete result: some checks read root-only files.",
		Example: "  sudo hyperion-trace scan\n" +
			"  sudo hyperion-trace scan --format json > report.json\n" +
			"  sudo hyperion-trace scan --fail-under 80 --skip KRN-006",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.exceptionsExplicit = cmd.Flags().Changed("exceptions")
			return runScan(cmd, o, version)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.format, "format", "f", "table", "output format: table or json")
	f.IntVar(&o.failUnder, "fail-under", 0, "exit with code 2 when the score is below this value (0-100)")
	f.StringSliceVar(&o.skip, "skip", nil, "check IDs to skip, e.g. KRN-006,MNT-004")
	f.StringSliceVar(&o.only, "only", nil, "run only these check IDs or categories (e.g. SSH,KRN-001)")
	f.StringVar(&o.minSeverity, "min-severity", "low", "ignore checks below this severity: low, medium, high, critical")
	f.BoolVar(&o.failedOnly, "failed-only", false, "table output: list only failed and errored checks")
	f.DurationVar(&o.timeout, "timeout", 2*time.Minute, "abort the scan after this long")
	f.StringVar(&o.exceptionsPath, "exceptions", exceptions.DefaultPath,
		"documented exceptions file (JSON); must be owned by root (or you) and not writable by others")
	f.BoolVar(&o.noExceptions, "no-exceptions", false, "ignore the exceptions file (strict scan)")
	f.StringVar(&o.profile, "profile", profiles.Default,
		"baseline variant: "+strings.Join(profiles.Names(), ", ")+" (see `hyperion-trace profiles`)")
	return cmd
}

func runScan(cmd *cobra.Command, o scanOptions, version string) error {
	if o.format != "table" && o.format != "json" {
		return fmt.Errorf("invalid --format %q: want table or json", o.format)
	}
	if o.failUnder < 0 || o.failUnder > 100 {
		return fmt.Errorf("invalid --fail-under %d: want 0-100", o.failUnder)
	}
	if o.timeout <= 0 {
		return fmt.Errorf("invalid --timeout %s: must be positive", o.timeout)
	}
	if o.noExceptions && o.exceptionsExplicit {
		return fmt.Errorf("--exceptions and --no-exceptions cannot be used together")
	}
	// Defense in depth: refuse to run with a profile table that breaks the
	// rules (tests enforce this too).
	if err := profiles.Validate(checks.All()); err != nil {
		return err
	}
	prof, err := profiles.Lookup(o.profile)
	if err != nil {
		return err
	}
	list, err := selectChecks(checks.All(), o)
	if err != nil {
		return err
	}
	// Exceptions are loaded before anything runs and fail closed: a file that
	// is unsafe or invalid stops the scan rather than being half-applied.
	var excepts *exceptions.Set
	if !o.noExceptions {
		excepts, err = exceptions.Load(o.exceptionsPath, o.exceptionsExplicit, os.Geteuid(), checks.All(), now())
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), o.timeout)
	defer cancel()

	h := newHost()
	r := report.Run(ctx, h, list, report.Options{Version: version, Exceptions: excepts, Now: now(), Profile: prof})
	if ctx.Err() != nil {
		return fmt.Errorf("scan aborted: %w", ctx.Err())
	}

	out := cmd.OutOrStdout()
	if o.format == "json" {
		err = report.WriteJSON(out, r)
	} else {
		width := 0
		if f, ok := out.(*os.File); ok {
			width, _, _ = term.GetSize(f.Fd())
		}
		err = report.WriteTable(colorprofile.NewWriter(out, os.Environ()), r,
			report.TableOptions{Width: width, FailedOnly: o.failedOnly})
	}
	if err != nil {
		return err
	}

	if o.failUnder > 0 && r.Score < o.failUnder {
		return &ExitError{Code: 2, Msg: fmt.Sprintf("score %d is below --fail-under %d", r.Score, o.failUnder)}
	}
	return nil
}

// selectChecks applies --only, --skip and --min-severity. Unknown IDs are an
// error: a typo in --skip must not silently leave a check running (or worse,
// a typo in --only silently run nothing).
func selectChecks(all []checks.Check, o scanOptions) ([]checks.Check, error) {
	minSev, err := checks.ParseSeverity(o.minSeverity)
	if err != nil {
		return nil, err
	}

	ids := map[string]bool{}
	categories := map[string]bool{}
	for _, c := range all {
		ids[c.ID] = true
		categories[strings.ToUpper(c.Category)] = true
		categories[strings.ToUpper(strings.SplitN(c.ID, "-", 2)[0])] = true
	}

	norm := func(vals []string) []string {
		var out []string
		for _, v := range vals {
			if v = strings.ToUpper(strings.TrimSpace(v)); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	skip := norm(o.skip)
	only := norm(o.only)
	for _, id := range skip {
		if !ids[id] {
			return nil, fmt.Errorf("unknown check ID %q in --skip (see `hyperion-trace checks`)", id)
		}
	}
	for _, v := range only {
		if !ids[v] && !categories[v] {
			return nil, fmt.Errorf("unknown check ID or category %q in --only (see `hyperion-trace checks`)", v)
		}
	}

	var out []checks.Check
	for _, c := range all {
		if slices.Contains(skip, c.ID) || c.Severity < minSev {
			continue
		}
		if len(only) > 0 && !slices.Contains(only, c.ID) &&
			!slices.Contains(only, strings.ToUpper(c.Category)) &&
			!slices.Contains(only, strings.SplitN(c.ID, "-", 2)[0]) {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no checks selected")
	}
	return out, nil
}
