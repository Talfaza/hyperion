// Package checks implements the Hyperion hardening baseline
// (iso/hyperion.md, Part II, Sections 4-9) as read-only host checks.
package checks

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

// Weight is how much a check counts toward the posture score.
func (s Severity) Weight() int {
	switch s {
	case Critical:
		return 10
	case High:
		return 5
	case Medium:
		return 3
	default:
		return 1
	}
}

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	default:
		return "low"
	}
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	case "critical":
		return Critical, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want low, medium, high or critical)", s)
}

type Status string

const (
	Pass  Status = "pass"
	Fail  Status = "fail"
	Skip  Status = "skip"
	Error Status = "error"
)

// Result is what a single check observed.
type Result struct {
	Status Status `json:"status"`
	// Detail explains the outcome: what was found, why it was skipped, or
	// what went wrong.
	Detail string `json:"detail,omitempty"`
}

func pass(format string, a ...any) Result {
	return Result{Status: Pass, Detail: fmt.Sprintf(format, a...)}
}
func fail(format string, a ...any) Result {
	return Result{Status: Fail, Detail: fmt.Sprintf(format, a...)}
}
func skip(format string, a ...any) Result {
	return Result{Status: Skip, Detail: fmt.Sprintf(format, a...)}
}
func errored(err error) Result {
	return Result{Status: Error, Detail: err.Error()}
}

type Check struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Control     string   `json:"control"`
	Severity    Severity `json:"severity"`
	Remediation string   `json:"remediation"`
	// NeedsRoot marks checks that read root-only files; when the scanner is
	// not root, a permission error is reported with a clearer hint.
	NeedsRoot bool `json:"needs_root"`

	run func(ctx context.Context, h *platform.Host) Result
}

// Run executes the check, converting panics into an Error result so one
// buggy or surprised check can never abort the whole scan.
func (c Check) Run(ctx context.Context, h *platform.Host) (r Result) {
	defer func() {
		if p := recover(); p != nil {
			r = Result{Status: Error, Detail: fmt.Sprintf("internal error: %v", p)}
		}
	}()
	if err := ctx.Err(); err != nil {
		return errored(err)
	}
	r = c.run(ctx, h)
	if r.Status == Error && c.NeedsRoot && !h.IsRoot {
		r.Detail += " (run as root)"
	}
	return r
}

var registry []Check

func register(cs ...Check) {
	for _, c := range cs {
		if c.run == nil || c.ID == "" {
			panic("checks: invalid check registration " + c.ID)
		}
		for _, existing := range registry {
			if existing.ID == c.ID {
				panic("checks: duplicate check ID " + c.ID)
			}
		}
		registry = append(registry, c)
	}
}

// All returns every registered check sorted by ID.
func All() []Check {
	out := slices.Clone(registry)
	slices.SortFunc(out, func(a, b Check) int { return strings.Compare(a.ID, b.ID) })
	return out
}
