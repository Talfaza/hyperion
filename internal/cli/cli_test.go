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
