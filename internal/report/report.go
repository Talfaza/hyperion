// Package report runs checks against a host and turns the results into a
// scored report that can be rendered as a table or JSON.
package report

import (
	"context"
	"sort"
	"time"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/exceptions"
	"github.com/Talfaza/hyperion/internal/platform"
)

// SchemaVersion 2 added the "excepted" status, score_strict and exception details.
const SchemaVersion = 2

type Finding struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Category    string          `json:"category"`
	Control     string          `json:"control"`
	Severity    checks.Severity `json:"severity"`
	Status      checks.Status   `json:"status"`
	Detail      string          `json:"detail,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	// Exception is set when an exception matched this check: Status is
	// "excepted" while it is valid, and stays "fail" once it has expired.
	Exception *ExceptionInfo `json:"exception,omitempty"`
}

type ExceptionInfo struct {
	Reason              string `json:"reason"`
	CompensatingControl string `json:"compensating_control"`
	ApprovedBy          string `json:"approved_by"`
	Expires             string `json:"expires"`
	Expired             bool   `json:"expired"`
}

// ExceptionsMeta ties a report to the exact exceptions file that shaped it.
type ExceptionsMeta struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	// Unused are exceptions that changed nothing (the check passed, was
	// skipped, errored, or was not run): candidates for removal.
	Unused []string `json:"unused,omitempty"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Family   string `json:"family"`
	Kernel   string `json:"kernel"`
}

type Summary struct {
	Pass     int `json:"pass"`
	Fail     int `json:"fail"`
	Skip     int `json:"skip"`
	Error    int `json:"error"`
	Excepted int `json:"excepted"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	ScannedAt     time.Time `json:"scanned_at"`
	RunningAsRoot bool      `json:"running_as_root"`
	Host          HostInfo  `json:"host"`
	Score         int       `json:"score"`
	// ScoreStrict counts excepted checks as failures: the posture without
	// any accepted risk.
	ScoreStrict int             `json:"score_strict"`
	Summary     Summary         `json:"summary"`
	Exceptions  *ExceptionsMeta `json:"exceptions,omitempty"`
	Findings    []Finding       `json:"findings"`
}

// Options control how a scan is turned into a report.
type Options struct {
	Version    string
	Exceptions *exceptions.Set // nil: none
	Now        time.Time       // for exception expiry; zero means time.Now()
}

// Run executes the given checks sequentially and builds a report.
func Run(ctx context.Context, h *platform.Host, list []checks.Check, opt Options) Report {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := Report{
		SchemaVersion: SchemaVersion,
		Tool:          "hyperion-trace",
		Version:       opt.Version,
		ScannedAt:     time.Now().UTC().Truncate(time.Second),
		RunningAsRoot: h.IsRoot,
		Host: HostInfo{
			Hostname: h.Hostname,
			OS:       h.OS.PrettyName,
			Family:   string(h.OS.Family),
			Kernel:   h.Kernel,
		},
		Findings: make([]Finding, 0, len(list)),
	}
	for _, c := range list {
		res := c.Run(ctx, h)
		f := Finding{
			ID: c.ID, Title: c.Title, Category: c.Category, Control: c.Control,
			Severity: c.Severity, Status: res.Status, Detail: res.Detail,
		}
		if res.Status == checks.Fail {
			f.Remediation = c.Remediation
		}
		applyException(&f, opt.Exceptions, now)
		r.Findings = append(r.Findings, f)
	}
	r.Summary, r.Score = Score(r.Findings)
	r.ScoreStrict = StrictScore(r.Findings)
	if opt.Exceptions != nil {
		r.Exceptions = &ExceptionsMeta{
			Path:   opt.Exceptions.Path,
			SHA256: opt.Exceptions.SHA256,
			Unused: unusedExceptions(opt.Exceptions, r.Findings),
		}
	}
	return r
}

// applyException turns a failing finding into an excepted one when a valid
// exception covers it. Passes, skips and errors are never changed: an
// exception accepts a known deviation, it cannot vouch for something the
// scanner could not verify.
func applyException(f *Finding, set *exceptions.Set, now time.Time) {
	e, ok := set.Lookup(f.ID)
	if !ok || f.Status != checks.Fail {
		return
	}
	f.Exception = &ExceptionInfo{
		Reason:              e.Reason,
		CompensatingControl: e.CompensatingControl,
		ApprovedBy:          e.ApprovedBy,
		Expires:             e.Expires,
		Expired:             e.Expired(now),
	}
	if f.Exception.Expired {
		f.Detail = "exception expired on " + e.Expires + "; " + f.Detail
		return
	}
	f.Status = checks.Excepted
}

func unusedExceptions(set *exceptions.Set, findings []Finding) []string {
	applied := map[string]bool{}
	for _, f := range findings {
		if f.Exception != nil {
			applied[f.ID] = true
		}
	}
	var unused []string
	for _, id := range set.IDs() {
		if !applied[id] {
			unused = append(unused, id)
		}
	}
	sort.Strings(unused)
	return unused
}

// Score computes the 0-100 posture score: passed weight divided by the weight
// of every check that applies. Errors count against the score because an
// unverifiable control is not a passing control. Skipped checks are excluded.
// A scan where nothing applies scores 0, never a misleading 100.
func Score(findings []Finding) (Summary, int) {
	var s Summary
	var earned, possible int
	for _, f := range findings {
		w := f.Severity.Weight()
		switch f.Status {
		case checks.Pass:
			s.Pass++
			earned += w
			possible += w
		case checks.Fail:
			s.Fail++
			possible += w
		case checks.Error:
			s.Error++
			possible += w
		case checks.Skip:
			s.Skip++
		case checks.Excepted:
			// Accepted risk: left out of the score like a skip, so it neither
			// raises nor lowers it. StrictScore counts it as a failure.
			s.Excepted++
		}
	}
	if possible == 0 {
		return s, 0
	}
	// Round down: a score should never overstate posture.
	return s, earned * 100 / possible
}

// StrictScore is Score with every excepted check counted as a failure.
func StrictScore(findings []Finding) int {
	strict := make([]Finding, len(findings))
	copy(strict, findings)
	for i := range strict {
		if strict[i].Status == checks.Excepted {
			strict[i].Status = checks.Fail
		}
	}
	_, score := Score(strict)
	return score
}
