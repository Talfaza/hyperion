package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/charmbracelet/colorprofile"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/profiles"
)

func profile(t *testing.T, name string) profiles.Profile {
	t.Helper()
	p, err := profiles.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestApplyProfileNotApplicableKeepsResult(t *testing.T) {
	ws := profile(t, "workstation")
	f := Finding{ID: "NET-002", Severity: checks.Medium, Status: checks.Fail, Detail: "cups.service running", Remediation: "disable it"}
	applyProfile(&f, ws)
	if f.Status != checks.Skip || f.Remediation != "" {
		t.Fatalf("not applicable should skip without a fix: %+v", f)
	}
	if f.Profile == nil || f.Profile.OriginalStatus != checks.Fail || f.Profile.OriginalSeverity != checks.Medium {
		t.Fatalf("original result must be kept: %+v", f.Profile)
	}
	if !strings.Contains(f.Detail, "workstation profile") || !strings.Contains(f.Detail, "cups.service running") {
		t.Errorf("detail should give the reason and the real result: %s", f.Detail)
	}
}

func TestApplyProfileRaise(t *testing.T) {
	ws := profile(t, "workstation")
	f := Finding{ID: "CRY-001", Severity: checks.Medium, Status: checks.Fail}
	applyProfile(&f, ws)
	if f.Severity != checks.High || f.Status != checks.Fail || f.Profile == nil || f.Profile.OriginalSeverity != checks.Medium {
		t.Fatalf("raise: %+v %+v", f, f.Profile)
	}
}

func TestServerProfileChangesNothing(t *testing.T) {
	srv := profile(t, "server")
	for _, c := range checks.All() {
		f := Finding{ID: c.ID, Severity: c.Severity, Status: checks.Fail}
		applyProfile(&f, srv)
		if f.Status != checks.Fail || f.Severity != c.Severity || f.Profile != nil {
			t.Fatalf("server profile changed %s", c.ID)
		}
	}
}

func TestProfileNeverTouchesCriticalChecks(t *testing.T) {
	for _, name := range profiles.Names() {
		p := profile(t, name)
		for _, c := range checks.All() {
			if c.Severity != checks.Critical {
				continue
			}
			f := Finding{ID: c.ID, Severity: c.Severity, Status: checks.Fail}
			applyProfile(&f, p)
			if f.Status != checks.Fail || f.Profile != nil {
				t.Errorf("%s profile changed critical check %s", name, c.ID)
			}
		}
	}
}

func TestBaselineScoreUndoesProfileAndExceptions(t *testing.T) {
	ws := profile(t, "workstation")
	findings := []Finding{
		{ID: "SSH-001", Severity: checks.Critical, Status: checks.Pass}, // 10
		{ID: "NET-002", Severity: checks.Medium, Status: checks.Fail},   // 3, n/a on workstation
		{ID: "CRY-001", Severity: checks.Medium, Status: checks.Fail},   // 3, raised to high (5)
		{ID: "KRN-006", Severity: checks.Medium, Status: checks.Fail},   // 3, excepted below
	}
	for i := range findings {
		applyProfile(&findings[i], ws)
	}
	findings[3].Status = checks.Excepted

	_, score := Score(findings) // 10 / (10 + 5) = 66
	if score != 66 {
		t.Errorf("profile score %d, want 66", score)
	}
	if s := StrictScore(findings); s != 55 { // 10 / (10 + 5 + 3) = 55
		t.Errorf("strict score %d, want 55", s)
	}
	if s := BaselineScore(findings); s != 52 { // 10 / (10 + 3 + 3 + 3) = 52
		t.Errorf("baseline score %d, want 52", s)
	}
}

func TestRenderProfile(t *testing.T) {
	ws := profile(t, "workstation")
	r := Report{RunningAsRoot: true, Profile: "workstation", Findings: []Finding{
		{ID: "SSH-001", Title: "root login", Severity: checks.Critical, Status: checks.Pass},
		{ID: "NET-002", Title: "services", Severity: checks.Medium, Status: checks.Fail, Detail: "cups.service"},
	}}
	applyProfile(&r.Findings[1], ws)
	r.Summary, r.Score = Score(r.Findings)
	r.ScoreStrict, r.ScoreBaseline = StrictScore(r.Findings), BaselineScore(r.Findings)
	var buf bytes.Buffer
	if err := WriteTable(&colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}, r, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"profile workstation (1 checks adjusted)", "full baseline"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q", want)
		}
	}
}
