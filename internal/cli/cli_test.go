package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/platform"
)

// fixtureHost points scans at a mostly empty fake filesystem.
func useFixtureHost(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/os-release", "ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu Test\"\n")
	write("/proc/sys/kernel/hostname", "fixture\n")
	write("/proc/sys/kernel/randomize_va_space", "2\n")
	run := (&platform.FakeRunner{}).Set("sshd -T", "permitrootlogin no\n", 0)
	old := newHost
	newHost = func() *platform.Host { return platform.NewHost(root, run, true) }
	t.Cleanup(func() { newHost = old })
}

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newRootCmd("test")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestScanJSON(t *testing.T) {
	useFixtureHost(t)
	out, err := execute(t, "scan", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Host     struct{ Hostname string }
		Findings []struct{ ID, Status string }
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if r.Host.Hostname != "fixture" || len(r.Findings) != len(checks.All()) {
		t.Fatalf("host=%q findings=%d", r.Host.Hostname, len(r.Findings))
	}
}

func TestScanTable(t *testing.T) {
	useFixtureHost(t)
	out, err := execute(t, "scan", "--only", "KRN-001,SSH-001")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HYPERION TRACE", "KRN-001", "SSH-001", "100"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestScanFailUnderExitCode(t *testing.T) {
	useFixtureHost(t)
	_, err := execute(t, "scan", "--format", "json", "--fail-under", "90")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 2 {
		t.Fatalf("want ExitError code 2, got %v", err)
	}
	if _, err := execute(t, "scan", "--format", "json", "--only", "KRN-001", "--fail-under", "100"); err != nil {
		t.Fatalf("passing scan should not fail: %v", err)
	}
}

func TestScanRejectsBadFlags(t *testing.T) {
	useFixtureHost(t)
	cases := [][]string{
		{"scan", "--format", "xml"},
		{"scan", "--fail-under", "101"},
		{"scan", "--fail-under", "-1"},
		{"scan", "--skip", "SSH-999"},
		{"scan", "--only", "NOPE"},
		{"scan", "--min-severity", "extreme"},
		{"scan", "--timeout", "0s"},
		{"scan", "unexpected-arg"},
		{"checks", "--format", "yaml"},
	}
	for _, args := range cases {
		if _, err := execute(t, args...); err == nil {
			t.Errorf("%v: expected an error", args)
		}
	}
}

func TestSelectChecks(t *testing.T) {
	all := checks.All()
	base := scanOptions{minSeverity: "low"}

	wantSSH := 0
	for _, c := range all {
		if strings.HasPrefix(c.ID, "SSH-") {
			wantSSH++
		}
	}
	got, err := selectChecks(all, scanOptions{minSeverity: "low", only: []string{"ssh"}})
	if err != nil || len(got) != wantSSH || wantSSH == 0 {
		t.Fatalf("--only ssh: %d checks (want %d), err %v", len(got), wantSSH, err)
	}
	got, _ = selectChecks(all, scanOptions{minSeverity: "low", only: []string{"Kernel"}})
	for _, c := range got {
		if c.Category != "Kernel" {
			t.Errorf("--only Kernel included %s", c.ID)
		}
	}
	got, _ = selectChecks(all, scanOptions{minSeverity: "critical"})
	for _, c := range got {
		if c.Severity != checks.Critical {
			t.Errorf("--min-severity critical included %s", c.ID)
		}
	}
	o := base
	o.skip = []string{" krn-006 "}
	got, _ = selectChecks(all, o)
	for _, c := range got {
		if c.ID == "KRN-006" {
			t.Error("--skip KRN-006 ignored")
		}
	}
	if len(got) != len(all)-1 {
		t.Errorf("skip removed %d checks", len(all)-len(got))
	}
	o = base
	o.only = []string{"KRN-001"}
	o.skip = []string{"KRN-001"}
	if _, err := selectChecks(all, o); err == nil {
		t.Error("empty selection should be an error")
	}
}

func TestChecksCommand(t *testing.T) {
	out, err := execute(t, "checks", "--format", "json")
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list) != len(checks.All()) {
		t.Fatalf("checks json: %d entries, err %v", len(list), err)
	}
}

func writeExceptions(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "exceptions.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, mode)
	return p
}

const krn006Exception = `{"version":1,"exceptions":[{"check":"KRN-006","reason":"Docker host needs IP forwarding","compensating_control":"default-deny forward chain","approved_by":"secops","expires":"2027-06-30"}]}`

func TestScanAppliesExceptions(t *testing.T) {
	useFixtureHost(t)
	old := now
	now = func() time.Time { return time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = old })

	p := writeExceptions(t, krn006Exception, 0o600)
	out, err := execute(t, "scan", "--format", "json", "--exceptions", p)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		ScoreStrict int `json:"score_strict"`
		Score       int
		Summary     struct{ Excepted int }
		Exceptions  struct{ Path, SHA256 string }
		Findings    []struct {
			ID, Status string
			Exception  *struct{ Reason string }
		}
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	// The fixture host has no ip_forward key, so KRN-006 fails and the
	// exception applies.
	found := false
	for _, f := range r.Findings {
		if f.ID == "KRN-006" {
			found = f.Status == "excepted" && f.Exception != nil && f.Exception.Reason != ""
		}
	}
	if !found || r.Summary.Excepted != 1 || r.Exceptions.Path != p || len(r.Exceptions.SHA256) != 64 {
		t.Fatalf("exception not applied/recorded: %s", out)
	}
	if r.ScoreStrict > r.Score {
		t.Errorf("strict score %d above score %d", r.ScoreStrict, r.Score)
	}

	// Expired: back to a failure.
	now = func() time.Time { return time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC) }
	out, _ = execute(t, "scan", "--format", "json", "--exceptions", p, "--only", "KRN-006")
	if !strings.Contains(out, `"status": "fail"`) || !strings.Contains(out, "exception expired") {
		t.Errorf("expired exception should fail again: %s", out)
	}
}

func TestScanFailsClosedOnBadExceptions(t *testing.T) {
	useFixtureHost(t)
	cases := map[string]string{
		"world writable": writeExceptions(t, krn006Exception, 0o666),
		"invalid json":   writeExceptions(t, `{"version":1,`, 0o600),
		"critical check": writeExceptions(t, strings.Replace(krn006Exception, "KRN-006", "AUTH-006", 1), 0o600),
		"missing file":   filepath.Join(t.TempDir(), "nope.json"),
	}
	for name, p := range cases {
		if out, err := execute(t, "scan", "--format", "json", "--exceptions", p); err == nil {
			t.Errorf("%s: scan ran (fail open):\n%.200s", name, out)
		}
	}
	if _, err := execute(t, "scan", "--exceptions", cases["invalid json"], "--no-exceptions"); err == nil {
		t.Error("--exceptions with --no-exceptions should be rejected")
	}
	// --no-exceptions ignores even a broken default file.
	if _, err := execute(t, "scan", "--format", "json", "--no-exceptions", "--only", "KRN-001"); err != nil {
		t.Errorf("--no-exceptions: %v", err)
	}
}

func TestScanProfiles(t *testing.T) {
	useFixtureHost(t)
	if _, err := execute(t, "scan", "--profile", "laptop"); err == nil {
		t.Error("unknown profile accepted")
	}
	out, err := execute(t, "scan", "--format", "json", "--profile", "container-host", "--only", "KRN-006,KRN-001")
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Profile       string
		ScoreBaseline int `json:"score_baseline"`
		Findings      []struct {
			ID, Status string
			Profile    *struct {
				OriginalStatus string `json:"original_status"`
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Profile != "container-host" {
		t.Errorf("profile %q", r.Profile)
	}
	for _, f := range r.Findings {
		if f.ID == "KRN-006" && (f.Status != "skip" || f.Profile == nil || f.Profile.OriginalStatus != "fail") {
			t.Errorf("KRN-006 on container-host: %+v", f)
		}
	}

	out, _ = execute(t, "profiles", "--format", "json")
	if !strings.Contains(out, "workstation") || !strings.Contains(out, "container-host") {
		t.Errorf("profiles command: %s", out)
	}
}
