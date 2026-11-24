package report

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/charmbracelet/colorprofile"

	"github.com/Talfaza/hyperion/internal/checks"
	"github.com/Talfaza/hyperion/internal/platform"
)

func f(id string, sev checks.Severity, st checks.Status) Finding {
	return Finding{ID: id, Title: "t " + id, Category: "C", Control: "A.8.9", Severity: sev, Status: st}
}

func TestScore(t *testing.T) {
	cases := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{"all pass", []Finding{f("a", checks.Critical, checks.Pass), f("b", checks.Low, checks.Pass)}, 100},
		{"all fail", []Finding{f("a", checks.High, checks.Fail)}, 0},
		{"weighted", []Finding{f("a", checks.Critical, checks.Pass), f("b", checks.Critical, checks.Fail)}, 50},
		// 10 earned of 10+5+3 = 55.5 -> rounds down
		{"round down", []Finding{f("a", checks.Critical, checks.Pass), f("b", checks.High, checks.Fail), f("c", checks.Medium, checks.Error)}, 55},
		{"skip excluded", []Finding{f("a", checks.Low, checks.Pass), f("b", checks.Critical, checks.Skip)}, 100},
		{"errors count against", []Finding{f("a", checks.Medium, checks.Pass), f("b", checks.Medium, checks.Error)}, 50},
		{"nothing applicable", []Finding{f("a", checks.Low, checks.Skip)}, 0},
		{"empty", nil, 0},
	}
	for _, c := range cases {
		if _, got := Score(c.findings); got != c.want {
			t.Errorf("%s: score %d, want %d", c.name, got, c.want)
		}
	}
	s, _ := Score([]Finding{f("a", 1, checks.Pass), f("b", 1, checks.Fail), f("c", 1, checks.Skip), f("d", 1, checks.Error)})
	if s != (Summary{Pass: 1, Fail: 1, Skip: 1, Error: 1}) {
		t.Errorf("summary %+v", s)
	}
}

func TestSanitizeStripsTerminalEscapes(t *testing.T) {
	cases := map[string]string{
		"\x1b[2J\x1b[Hfake all clear": "[2J[Hfake all clear",
		"line1\nline2\r":              "line1line2",
		"tab\there":                   "tab here",
		"bidi \u202eevil\u202c":       "bidi evil",
		"zero\u200bwidth":             "zerowidth",
		"\x07bell \x9b31m csi":        "bell 31m csi",
		"café ✓ 日本":                   "café ✓ 日本",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add("\x1b]52;c;ZXZpbA==\x07 osc52 clipboard")
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range Sanitize(s) {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("control rune %U survived in %q", r, Sanitize(s))
			}
		}
	})
}

func sampleReport() Report {
	r := Report{
		SchemaVersion: SchemaVersion, Tool: "hyperion-trace", Version: "test",
		Host: HostInfo{Hostname: "web-01\x1b[31m", OS: "Ubuntu 24.04", Family: "debian", Kernel: "6.8.0"},
		Findings: []Finding{
			f("SSH-001", checks.Critical, checks.Pass),
			{ID: "SSH-002", Title: "pw auth", Category: "SSH", Control: "A.8.2", Severity: checks.High, Status: checks.Fail,
				Detail: "passwordauthentication yes\x1b]0;pwned\x07", Remediation: "Set `PasswordAuthentication no`"},
			{ID: "AUTH-005", Title: "a", Severity: checks.Low, Status: checks.Error, Detail: "permission denied"},
			{ID: "AUTH-006", Title: "b", Severity: checks.Critical, Status: checks.Error, Detail: "permission denied"},
			f("MAC-001", checks.High, checks.Skip),
		},
	}
	r.Summary, r.Score = Score(r.Findings)
	return r
}

func TestWriteTableNoInjectionAndContent(t *testing.T) {
	// Render in full color (the colorprofile writer would otherwise strip
	// escapes itself and hide a missing Sanitize) and look for the exact
	// sequences planted in host data.
	var colored bytes.Buffer
	if err := WriteTable(&colorprofile.Writer{Forward: &colored, Profile: colorprofile.TrueColor},
		sampleReport(), TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	for _, injected := range []string{"\x1b]0;pwned", "\x07", "web-01\x1b[31m"} {
		if strings.Contains(colored.String(), injected) {
			t.Fatalf("host-supplied escape %q reached the terminal", injected)
		}
	}

	var buf bytes.Buffer
	if err := WriteTable(&colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY},
		sampleReport(), TableOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"SSH-001", "SSH-002", "passwordauthentication yes", "PasswordAuthentication no", "AUTH-006 (same error)", "Not running as root"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteTableFailedOnly(t *testing.T) {
	var buf bytes.Buffer
	w := &colorprofile.Writer{Forward: &buf, Profile: colorprofile.NoTTY}
	r := sampleReport()
	r.RunningAsRoot = true
	if err := WriteTable(w, r, TableOptions{FailedOnly: true}); err != nil {
		t.Fatal(err)
	}
	table := strings.SplitN(buf.String(), "Findings", 2)[0]
	if strings.Contains(table, "SSH-001") || strings.Contains(table, "MAC-001") {
		t.Errorf("--failed-only table still lists passing/skipped checks:\n%s", table)
	}
	if strings.Contains(buf.String(), "Not running as root") {
		t.Error("root warning shown when running as root")
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(buf.String(), '\x1b') {
		t.Fatal("raw ESC in JSON output")
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	findings := back["findings"].([]any)
	first := findings[1].(map[string]any)
	if first["severity"] != "high" || first["status"] != "fail" {
		t.Errorf("severity/status not serialized as text: %v", first)
	}
	if back["schema_version"].(float64) != SchemaVersion {
		t.Errorf("schema_version %v", back["schema_version"])
	}
}

func TestRunCallsProgressInOrder(t *testing.T) {
	list := checks.All()[:4]
	h := platform.NewHost(t.TempDir(), &platform.FakeRunner{}, true)
	var seen []string
	Run(context.Background(), h, list, Options{Progress: func(i, total int, c checks.Check) {
		if total != len(list) || i != len(seen) {
			t.Errorf("progress(%d, %d, %s) out of order", i, total, c.ID)
		}
		seen = append(seen, c.ID)
	}})
	if len(seen) != len(list) {
		t.Fatalf("progress called %d times, want %d", len(seen), len(list))
	}
}
