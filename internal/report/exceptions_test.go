package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/colorprofile"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/exceptions"
)

var day = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func exceptionSet(t *testing.T, ids ...string) *exceptions.Set {
	t.Helper()
	var entries []string
	for _, id := range ids {
		expires := "2027-06-30"
		if strings.HasSuffix(id, "!expired") {
			id = strings.TrimSuffix(id, "!expired")
			expires = "2026-10-01"
		}
		entries = append(entries, `{"check":"`+id+`","reason":"accepted for this test case","compensating_control":"compensating control text","approved_by":"tester","expires":"`+expires+`"}`)
	}
	set, err := exceptions.Parse([]byte(`{"version":1,"exceptions":[`+strings.Join(entries, ",")+`]}`), checks.All(), day)
	if err != nil {
		t.Fatal(err)
	}
	set.Path = "/etc/hyperion/exceptions.json"
	return set
}

func TestApplyException(t *testing.T) {
	set := exceptionSet(t, "KRN-006", "CRY-001!expired", "MNT-004", "LOG-002")

	fail := Finding{ID: "KRN-006", Severity: checks.Medium, Status: checks.Fail, Detail: "ip_forward = 1"}
	applyException(&fail, set, day)
	if fail.Status != checks.Excepted || fail.Exception == nil || fail.Exception.Expired {
		t.Errorf("valid exception on a failure: %+v", fail)
	}

	expired := Finding{ID: "CRY-001", Severity: checks.Medium, Status: checks.Fail, Detail: "not on LUKS"}
	applyException(&expired, set, day)
	if expired.Status != checks.Fail || !expired.Exception.Expired || !strings.HasPrefix(expired.Detail, "exception expired on 2026-10-01") {
		t.Errorf("expired exception must stay a failure and say so: %+v", expired)
	}

	// An exception can't turn an error into anything: unverified stays unverified.
	errored := Finding{ID: "LOG-002", Severity: checks.Medium, Status: checks.Error, Detail: "permission denied"}
	applyException(&errored, set, day)
	if errored.Status != checks.Error || errored.Exception != nil {
		t.Errorf("exception changed an error: %+v", errored)
	}

	passed := Finding{ID: "MNT-004", Severity: checks.Low, Status: checks.Pass}
	applyException(&passed, set, day)
	if passed.Status != checks.Pass || passed.Exception != nil {
		t.Errorf("exception changed a pass: %+v", passed)
	}

	none := Finding{ID: "SSH-002", Severity: checks.High, Status: checks.Fail}
	applyException(&none, nil, day)
	if none.Status != checks.Fail {
		t.Error("nil set changed a finding")
	}
}

func TestScoresWithExceptions(t *testing.T) {
	findings := []Finding{
		f("a", checks.Medium, checks.Pass),     // 3
		f("b", checks.Medium, checks.Fail),     // 3
		f("c", checks.Medium, checks.Excepted), // 3
	}
	s, score := Score(findings)
	if s.Excepted != 1 || score != 50 { // excepted left out: 3 / 6
		t.Errorf("score %d excepted %d, want 50 and 1", score, s.Excepted)
	}
	if strict := StrictScore(findings); strict != 33 { // excepted counted as failed: 3 / 9
		t.Errorf("strict score %d, want 33", strict)
	}
	if findings[2].Status != checks.Excepted {
		t.Error("StrictScore mutated its input")
	}
}

func TestUnusedExceptions(t *testing.T) {
	set := exceptionSet(t, "KRN-006", "MNT-004", "FIM-001")
	findings := []Finding{
		{ID: "KRN-006", Status: checks.Excepted, Exception: &ExceptionInfo{}},
		{ID: "MNT-004", Status: checks.Pass},
		// FIM-001 not in the scan at all
	}
	got := unusedExceptions(set, findings)
	if strings.Join(got, ",") != "FIM-001,MNT-004" {
		t.Errorf("unused = %v", got)
	}
}

func TestRenderExceptions(t *testing.T) {
	r := Report{
		RunningAsRoot: true,
		Exceptions:    &ExceptionsMeta{Path: "/etc/hyperion/exceptions.json", SHA256: strings.Repeat("ab", 32), Unused: []string{"MNT-004"}},
		Findings: []Finding{
			f("SSH-001", checks.Critical, checks.Pass),
			{ID: "KRN-006", Title: "IP forwarding", Severity: checks.Medium, Status: checks.Excepted, Detail: "ip_forward = 1",
				Exception: &ExceptionInfo{Reason: "Docker host\x1b[2J", CompensatingControl: "forward chain default deny", ApprovedBy: "secops", Expires: "2027-06-30"}},
		},
	}
	r.Summary, r.Score = Score(r.Findings)
	r.ScoreStrict = StrictScore(r.Findings)
	var buf bytes.Buffer
	if err := WriteTable(&colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}, r, TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"EXCEPT", "strict", "1 excepted", "Docker host", "secops", "until 2027-06-30", "abababababab", "Unused exceptions", "MNT-004"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}

	// Colour output must not carry the escape planted in the reason.
	var colored bytes.Buffer
	WriteTable(&colorprofile.Writer{Forward: &colored, Profile: colorprofile.TrueColor}, r, TableOptions{Width: 100})
	if strings.Contains(colored.String(), "\x1b[2J") {
		t.Error("escape sequence from the exceptions file reached the terminal")
	}
}
