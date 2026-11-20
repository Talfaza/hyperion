//go:build vmtest

// Package vm runs hyperion-trace inside throwaway Ksar microVMs on several
// Linux distributions. It is excluded from normal builds and `go test ./...`
// by the vmtest build tag; run it with `make vm-test`.
//
// The scanner itself stays read-only. harden.sh is a test fixture that changes
// the guest so the pass paths can be checked, and it refuses to run outside a
// Ksar VM.
//
// Environment:
//
//	HYPERION_BIN  scanner binary to test (default: built into a temp dir)
//	KSAR          ksar binary (default: ~/Forks/Ksar/ksar)
//	KSAR_IMAGES   directory of distro image tars (default: ~/Forks/Ksar/build)
package vm

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type distro struct {
	name, image, family string
	allow               string // package mirrors the VM may reach while hardening
	mem                 string
}

// hardenable distros have a harden.sh branch; the rest are scanned stock only.
var hardenable = []distro{
	{"ubuntu", "ubuntu_24.04", "debian", "archive.ubuntu.com,security.ubuntu.com", "1G"},
	{"debian", "debian_bookworm-slim", "debian", "deb.debian.org", "1G"},
	{"fedora", "fedora_41", "rhel", "*.fedoraproject.org,*.fedoraproject.org:443", "1536M"},
	{"arch", "archlinux_latest", "arch", "fastly.mirror.pkgbuild.com,geo.mirror.pkgbuild.com", "2G"},
}

var stockOnly = []distro{
	{name: "opensuse", image: "opensuse_tumbleweed", family: "unknown"},
	{name: "alpine", image: "alpine_3.20", family: "unknown"},
}

// envLimited are checks the Ksar guest cannot satisfy no matter how the
// distro is configured: its kernel has no Yama, SYN cookies, LSM or
// nftables, and there is no systemd. Any status is accepted for them
// (correctness of those paths is covered by unit tests).
var envLimited = map[string]bool{
	"KRN-004": true, "KRN-005": true, "MAC-001": true,
	"NET-001": true, "NET-002": true, "TIME-001": true, "UPD-002": true,
	"LOG-002": true, // auditd needs systemd and kernel audit support
	"CRY-001": true, // the guest root is an overlay, so CRY-001 correctly skips
}

// distroLimited are checks one distro cannot pass, with the reason.
var distroLimited = map[string]map[string]string{
	"arch": {"FIM-001": "AIDE is only in the AUR, not Arch's official repositories"},
}

type finding struct {
	ID, Status, Detail, Severity string
	Profile                      *struct {
		OriginalStatus string `json:"original_status"`
	}
}

type report struct {
	Host struct {
		Family string
	}
	Score         int
	ScoreBaseline int `json:"score_baseline"`
	Profile       string
	Findings      []finding
}

func (r report) byID() map[string]finding {
	m := map[string]finding{}
	for _, f := range r.Findings {
		m[f.ID] = f
	}
	return m
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type harness struct {
	ksar, images, bin, harden string
}

func setup(t *testing.T) harness {
	t.Helper()
	home, _ := os.UserHomeDir()
	h := harness{
		ksar:   env("KSAR", filepath.Join(home, "Forks/Ksar/ksar")),
		images: env("KSAR_IMAGES", filepath.Join(home, "Forks/Ksar/build")),
		bin:    os.Getenv("HYPERION_BIN"),
	}
	if _, err := os.Stat(h.ksar); err != nil {
		t.Skipf("ksar not found at %s (set KSAR)", h.ksar)
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("/dev/kvm not available")
	}
	if h.bin == "" {
		h.bin = filepath.Join(t.TempDir(), "hyperion-trace")
		build := exec.Command("go", "build", "-o", h.bin, "../../cmd/hyperion-trace")
		build.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	var err error
	if h.harden, err = filepath.Abs("harden.sh"); err != nil {
		t.Fatal(err)
	}
	return h
}

// run boots a VM for d, copies the scanner (and harden.sh) in, runs script
// with sh, and returns its stdout. network enables the distro's mirrors.
func (h harness) run(t *testing.T, d distro, network bool, script string) []byte {
	t.Helper()
	image := filepath.Join(h.images, d.image+".tar")
	if _, err := os.Stat(image); err != nil {
		t.Skipf("image %s not found", image)
	}
	mem := d.mem
	if mem == "" {
		mem = "512M"
	}
	args := []string{"run", "-mem", mem, "-timeout", "25m", "-image", image,
		"-copy", h.bin + ":/hyperion-trace", "-copy", h.harden + ":/harden.sh"}
	if network {
		args = append(args, "-net", "allow", "-allow", d.allow)
	}
	args = append(args, "--", "sh", "-c", script)

	cmd := exec.Command(h.ksar, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s VM failed: %v\n%s", d.name, err, filterKsar(stderr.String()))
	}
	return stdout.Bytes()
}

// filterKsar drops Ksar's per-connection network log lines.
func filterKsar(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(line, "[ksar] net:") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func parse(t *testing.T, data []byte) report {
	t.Helper()
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatalf("invalid JSON report: %v\n%s", err, data)
	}
	return r
}

// sanity applies to every scan: no crashed checks, only known statuses.
func sanity(t *testing.T, r report) {
	t.Helper()
	for _, f := range r.Findings {
		switch f.Status {
		case "pass", "fail", "skip", "error":
		default:
			t.Errorf("%s: unknown status %q", f.ID, f.Status)
		}
		if strings.Contains(f.Detail, "internal error") {
			t.Errorf("%s panicked: %s", f.ID, f.Detail)
		}
	}
}

func TestGuardRefusesOutsideKsar(t *testing.T) {
	if strings.HasSuffix(strings.TrimSpace(mustOutput(t, "uname", "-r")), "-ksar") {
		t.Skip("running inside a Ksar guest")
	}
	cmd := exec.Command("sh", "harden.sh")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 99 || !strings.Contains(string(out), "refusing to run") {
		t.Fatalf("harden.sh must refuse to run on the host (exit 99), got %v:\n%s", err, out)
	}
}

func TestStockImages(t *testing.T) {
	h := setup(t)
	for _, d := range append(append([]distro{}, hardenable...), stockOnly...) {
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			r := parse(t, h.run(t, d, false, "/hyperion-trace scan --format json"))
			sanity(t, r)
			if r.Host.Family != d.family {
				t.Errorf("family %q, want %q", r.Host.Family, d.family)
			}
		})
	}
}

func TestHardenedPassesBaseline(t *testing.T) {
	h := setup(t)
	for _, d := range hardenable {
		t.Run(d.name, func(t *testing.T) {
			r := parse(t, h.run(t, d, true, "sh /harden.sh && /hyperion-trace scan --format json"))
			sanity(t, r)
			got := r.byID()
			for _, f := range r.Findings {
				if envLimited[f.ID] || f.ID == "UPD-001" {
					continue
				}
				if why, ok := distroLimited[d.name][f.ID]; ok {
					t.Logf("tolerated %s on %s: %s", f.ID, d.name, why)
					continue
				}
				if f.Status != "pass" {
					t.Errorf("%s: %s (%s), want pass", f.ID, f.Status, f.Detail)
				}
			}
			wantUpd := "pass"
			if d.family == "arch" {
				wantUpd = "skip" // Arch discourages unattended upgrades
			}
			if s := got["UPD-001"].Status; s != wantUpd {
				t.Errorf("UPD-001: %s (%s), want %s", s, got["UPD-001"].Detail, wantUpd)
			}
			for _, id := range []string{"SSH-001", "SSH-007"} {
				if strings.Contains(got[id].Detail, "config files") {
					t.Errorf("%s was graded from the files, not real sshd -T: %s", id, got[id].Detail)
				}
			}
			t.Logf("%s score %d", d.name, r.Score)
		})
	}
}

// TestSSHScenarios checks, against a real OpenSSH (Debian 12, 9.2), the
// cases where `sshd -T` alone is misleading.
func TestSSHScenarios(t *testing.T) {
	h := setup(t)
	d := hardenable[1]
	script := `set -e
sh /harden.sh
scan() { echo "=== $1"; /hyperion-trace scan --only SSH --format json; }
cp /etc/ssh/sshd_config /tmp/sshd_config.orig

printf 'Match User backup\n    PasswordAuthentication yes\n' >> /etc/ssh/sshd_config
scan match
cp /tmp/sshd_config.orig /etc/ssh/sshd_config

rm -f /etc/ssh/ssh_host_*
scan nokeys

echo 'KexAlgorithms mlkem768x25519-sha256' > /etc/ssh/sshd_config.d/000-pq.conf
scan badkex
`
	out := string(h.run(t, d, true, script))
	scenarios := map[string]report{}
	for _, part := range strings.Split(out, "=== ")[1:] {
		name, body, _ := strings.Cut(part, "\n")
		scenarios[name] = parse(t, []byte(body))
	}

	t.Run("match block weakens password auth", func(t *testing.T) {
		f := scenarios["match"].byID()["SSH-002"]
		if f.Status != "fail" || !strings.Contains(f.Detail, "Match User backup") {
			t.Errorf("SSH-002: %s (%s), want fail naming the Match block", f.Status, f.Detail)
		}
	})
	t.Run("no host keys falls back to files", func(t *testing.T) {
		for _, f := range scenarios["nokeys"].Findings {
			if f.Status != "pass" || !strings.Contains(f.Detail, "no host keys yet") {
				t.Errorf("%s: %s (%s), want pass with the host-key note", f.ID, f.Status, f.Detail)
			}
		}
	})
	t.Run("unsupported algorithm is an error", func(t *testing.T) {
		for _, f := range scenarios["badkex"].Findings {
			if f.Status != "error" || !strings.Contains(f.Detail, "Unsupported KEX algorithm") {
				t.Errorf("%s: %s (%s), want error quoting sshd", f.ID, f.Status, f.Detail)
			}
		}
	})
}

func mustOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

var allProfiles = []string{"server", "workstation", "container-host"}

// profileScript scans with every profile, each report preceded by a marker.
func profileScript(binary string) string {
	var b strings.Builder
	for _, p := range allProfiles {
		b.WriteString("echo '=== " + p + "'; " + binary + " scan --no-exceptions --format json --profile " + p + "; ")
	}
	return b.String()
}

func splitReports(t *testing.T, out string) map[string]report {
	t.Helper()
	reports := map[string]report{}
	for _, part := range strings.Split(out, "=== ")[1:] {
		name, body, _ := strings.Cut(part, "\n")
		reports[name] = parse(t, []byte(body))
	}
	return reports
}

// checkProfileInvariants: whatever a profile does, the full-baseline score
// and every critical check must be identical, the recorded original status
// must match what the server profile saw, and server must change nothing.
func checkProfileInvariants(t *testing.T, label string, reports map[string]report) {
	t.Helper()
	server, ok := reports["server"]
	if !ok {
		t.Fatalf("%s: no server report", label)
	}
	base := server.byID()
	for _, p := range allProfiles {
		r, ok := reports[p]
		if !ok {
			t.Errorf("%s: no %s report", label, p)
			continue
		}
		sanity(t, r)
		if r.Profile != p {
			t.Errorf("%s %s: report says profile %q", label, p, r.Profile)
		}
		if r.ScoreBaseline != server.ScoreBaseline {
			t.Errorf("%s %s: full-baseline score %d differs from server's %d", label, p, r.ScoreBaseline, server.ScoreBaseline)
		}
		changed := 0
		for _, f := range r.Findings {
			if f.Severity == "critical" && f.Status != base[f.ID].Status {
				t.Errorf("%s %s changed critical check %s: %s -> %s", label, p, f.ID, base[f.ID].Status, f.Status)
			}
			if f.Profile != nil {
				changed++
				if f.Profile.OriginalStatus != base[f.ID].Status {
					t.Errorf("%s %s: %s original status %s, server saw %s", label, p, f.ID, f.Profile.OriginalStatus, base[f.ID].Status)
				}
			}
		}
		if p == "server" && (changed != 0 || r.Score != r.ScoreBaseline) {
			t.Errorf("%s: server profile changed %d checks (score %d, baseline %d)", label, changed, r.Score, r.ScoreBaseline)
		}
		t.Logf("%s %-15s score %3d  baseline %3d  adjusted %d", label, p, r.Score, r.ScoreBaseline, changed)
	}
}

// TestProfiles scans stock Ksar images under every profile.
func TestProfiles(t *testing.T) {
	h := setup(t)
	for _, d := range []distro{hardenable[0], hardenable[2]} { // ubuntu, fedora
		t.Run(d.name, func(t *testing.T) {
			t.Parallel()
			checkProfileInvariants(t, d.name, splitReports(t, string(h.run(t, d, false, profileScript("/hyperion-trace")))))
		})
	}
}
