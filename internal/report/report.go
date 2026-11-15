// Package report runs checks against a host and turns the results into a
// scored report that can be rendered as a table or JSON.
package report

import (
	"context"
	"time"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/platform"
)

const SchemaVersion = 1

type Finding struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Category    string          `json:"category"`
	Control     string          `json:"control"`
	Severity    checks.Severity `json:"severity"`
	Status      checks.Status   `json:"status"`
	Detail      string          `json:"detail,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Family   string `json:"family"`
	Kernel   string `json:"kernel"`
}

type Summary struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Skip  int `json:"skip"`
	Error int `json:"error"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	ScannedAt     time.Time `json:"scanned_at"`
	RunningAsRoot bool      `json:"running_as_root"`
	Host          HostInfo  `json:"host"`
	Score         int       `json:"score"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

// Run executes the given checks sequentially and builds a report.
func Run(ctx context.Context, h *platform.Host, list []checks.Check, version string) Report {
	r := Report{
		SchemaVersion: SchemaVersion,
		Tool:          "hyperion-trace",
		Version:       version,
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
		r.Findings = append(r.Findings, f)
	}
	r.Summary, r.Score = Score(r.Findings)
	return r
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
		}
	}
	if possible == 0 {
		return s, 0
	}
	// Round down: a score should never overstate posture.
	return s, earned * 100 / possible
}
