package checks

import (
	"context"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---- file permissions ---------------------------------------------------------

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestEvalFileMode(t *testing.T) {
	cases := []struct {
		info fakeInfo
		max  fs.FileMode
		want Status
	}{
		{fakeInfo{0o644, 0}, 0o644, Pass},
		{fakeInfo{0o600, 0}, 0o644, Pass},
		{fakeInfo{0o000, 0}, 0o640, Pass},
		{fakeInfo{0o666, 0}, 0o644, Fail},
		{fakeInfo{0o644, 1000}, 0o644, Fail},
		{fakeInfo{0o640 | fs.ModeSetuid, 0}, 0o640, Fail},
		{fakeInfo{0o644 | fs.ModeSymlink, 0}, 0o644, Fail},
	}
	for _, c := range cases {
		if got := evalFileMode("/etc/x", c.info, c.max); got.Status != c.want {
			t.Errorf("mode %v uid %d: %s (%s), want %s", c.info.mode, c.info.uid, got.Status, got.Detail, c.want)
		}
	}
}

func TestFileModeOnDisk(t *testing.T) {
	f := newFixture(t).fileMode("/etc/shadow", "", 0o644)
	r := f.check("FILE-002")
	expect(t, "FILE-002", r, Fail) // too permissive (and, unless root, wrong owner)
	expect(t, "FILE-003", f.check("FILE-003"), Skip)
	expect(t, "FILE-001", f.check("FILE-001"), Error) // missing /etc/passwd
	if os.Geteuid() != 0 {
		r = newFixture(t).fileMode("/etc/passwd", "", 0o644).check("FILE-001")
		if !strings.Contains(r.Detail, "owned by uid") {
			t.Errorf("non-root-owned file should fail ownership: %s", r.Detail)
		}
	}
}

func TestUmask(t *testing.T) {
	f := newFixture(t).file("/etc/login.defs", "UMASK 027\n").file("/etc/profile", "umask 077\n")
	expect(t, "FILE-004", f.check("FILE-004"), Pass)

	f = newFixture(t).file("/etc/login.defs", "UMASK 022\n")
	expect(t, "FILE-004", f.check("FILE-004"), Fail)

	f = newFixture(t).file("/etc/login.defs", "UMASK 027\n").file("/etc/profile.d/x.sh", "  umask 002\n")
	r := f.check("FILE-004")
	expect(t, "FILE-004", r, Fail)
	if !strings.Contains(r.Detail, "x.sh") {
		t.Errorf("detail: %s", r.Detail)
	}
}

// ---- mounts -------------------------------------------------------------------

const goodMounts = `/dev/sda1 / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0
/dev/sda2 /var/tmp ext4 rw,nosuid,nodev,noexec 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0
/dev/sda3 /var ext4 rw,nosuid,nodev 0 0
/dev/sda4 /home ext4 rw,nosuid,nodev 0 0
`

func TestMounts(t *testing.T) {
	f := newFixture(t).file("/proc/self/mounts", goodMounts)
	for _, id := range []string{"MNT-001", "MNT-002", "MNT-003", "MNT-004", "MNT-005"} {
		expect(t, id, f.check(id), Pass)
	}

	// Over-mount: the last entry for /tmp wins and lacks noexec.
	f = newFixture(t).file("/proc/self/mounts", goodMounts+"tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n")
	r := f.check("MNT-001")
	expect(t, "MNT-001", r, Fail)
	if !strings.Contains(r.Detail, "noexec") {
		t.Errorf("detail: %s", r.Detail)
	}

	f = newFixture(t).file("/proc/self/mounts", "/dev/sda1 / ext4 rw 0 0\n")
	expect(t, "MNT-004", f.check("MNT-004"), Fail)
}

func TestUnescapeMount(t *testing.T) {
	cases := map[string]string{
		`/mnt/my\040disk`: "/mnt/my disk",
		`/a\134b`:         `/a\b`,
		`/trailing\`:      `/trailing\`,
		`/short\04`:       `/short\04`,
		`/bad\999`:        `/bad\999`,
		`/end\040`:        "/end ",
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzParseMounts(f *testing.F) {
	f.Add(goodMounts + `x /a\040b\ c d\`)
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseMounts([]byte(s))
		_ = unescapeMount(s)
	})
}

// ---- kernel -------------------------------------------------------------------

func sysctlFixture(t *testing.T, values map[string]string) *fixture {
	f := newFixture(t)
	for k, v := range values {
		f.file(sysctlPath(k), v+"\n")
	}
	return f
}

func TestSysctlRules(t *testing.T) {
	good := map[string]string{}
	for _, r := range sysctlRules {
		for _, k := range r.keys {
			good[k] = r.want
		}
	}
	f := sysctlFixture(t, good)
	for _, r := range sysctlRules {
		expect(t, r.id, f.check(r.id), Pass)
	}

	f = sysctlFixture(t, map[string]string{"kernel.yama.ptrace_scope": "3", "kernel.randomize_va_space": "1"}).dir("/proc/sys/net/ipv6")
	expect(t, "KRN-004", f.check("KRN-004"), Pass) // >= rule
	expect(t, "KRN-001", f.check("KRN-001"), Fail)
	expect(t, "KRN-009", f.check("KRN-009"), Fail) // missing key

	f = sysctlFixture(t, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "0"}).dir("/etc/kubernetes")
	r := f.check("KRN-006")
	expect(t, "KRN-006", r, Fail)
	if !strings.Contains(r.Detail, "container") {
		t.Errorf("KRN-006 should hint about container hosts: %s", r.Detail)
	}
}

func TestSysctlIPv6AndDefaultInterfaces(t *testing.T) {
	good := map[string]string{}
	for _, r := range sysctlRules {
		for _, k := range r.keys {
			good[k] = r.want
		}
	}
	with := func(overrides map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		for k, v := range overrides {
			m[k] = v
		}
		return m
	}

	// IPv4 "all" is hardened but new interfaces (default) still accept redirects.
	r := sysctlFixture(t, with(map[string]string{"net.ipv4.conf.default.accept_redirects": "1"})).check("KRN-007")
	expect(t, "KRN-007 default", r, Fail)
	if !strings.Contains(r.Detail, "net.ipv4.conf.default.accept_redirects = 1") {
		t.Errorf("detail: %s", r.Detail)
	}

	// IPv4 fully hardened, IPv6 wide open: the old IPv4-only check passed here.
	r = sysctlFixture(t, with(map[string]string{"net.ipv6.conf.all.accept_redirects": "1"})).check("KRN-007")
	expect(t, "KRN-007 ipv6", r, Fail)
	expect(t, "KRN-006 ipv6 forwarding", sysctlFixture(t, with(map[string]string{"net.ipv6.conf.all.forwarding": "1"})).check("KRN-006"), Fail)
	expect(t, "KRN-013 ipv6 source route", sysctlFixture(t, with(map[string]string{"net.ipv6.conf.default.accept_source_route": "1"})).check("KRN-013"), Fail)
	expect(t, "KRN-014 ra", sysctlFixture(t, with(map[string]string{"net.ipv6.conf.all.accept_ra": "1"})).check("KRN-014"), Fail)

	// IPv6 compiled out / disabled: IPv6 keys are satisfied, IPv4 still checked.
	ipv4Only := map[string]string{}
	for k, v := range good {
		if !strings.HasPrefix(k, "net.ipv6.") {
			ipv4Only[k] = v
		}
	}
	f := sysctlFixture(t, ipv4Only)
	r = f.check("KRN-007")
	expect(t, "KRN-007 no ipv6", r, Pass)
	if !strings.Contains(r.Detail, "IPv6 is disabled") {
		t.Errorf("detail: %s", r.Detail)
	}
	r = f.check("KRN-014")
	expect(t, "KRN-014 no ipv6", r, Pass)

	// IPv6 present but a key missing is not excused.
	missing := with(nil)
	delete(missing, "net.ipv6.conf.default.accept_ra")
	r = sysctlFixture(t, missing).check("KRN-014")
	expect(t, "KRN-014 missing key", r, Fail)
}

func TestSysctlRemediationListsEveryKey(t *testing.T) {
	for _, r := range sysctlRules {
		rem := r.remediation()
		for _, k := range r.keys {
			if !strings.Contains(rem, k) {
				t.Errorf("%s remediation misses %s", r.id, k)
			}
		}
	}
}

// ---- MAC ----------------------------------------------------------------------

func TestMAC(t *testing.T) {
	expect(t, "selinux enforcing", newFixture(t).file("/sys/fs/selinux/enforce", "1").check("MAC-001"), Pass)
	expect(t, "selinux permissive", newFixture(t).file("/sys/fs/selinux/enforce", "0").check("MAC-001"), Fail)
	expect(t, "rhel no selinux", newFixture(t).rhel().check("MAC-001"), Fail)

	aa := newFixture(t).file("/sys/module/apparmor/parameters/enabled", "Y\n")
	expect(t, "apparmor unknown profiles", aa.check("MAC-001"), Pass)
	aa.file("/sys/kernel/security/apparmor/profiles", "/usr/sbin/cupsd (enforce)\nfoo (complain)\n")
	expect(t, "apparmor enforcing", aa.check("MAC-001"), Pass)

	aa = newFixture(t).file("/sys/module/apparmor/parameters/enabled", "Y\n").
		file("/sys/kernel/security/apparmor/profiles", "foo (complain)\n")
	expect(t, "apparmor all complain", aa.check("MAC-001"), Fail)
}

// ---- network ------------------------------------------------------------------

func TestFirewall(t *testing.T) {
	f := newFixture(t).dir("/run/systemd/system").cmd("systemctl is-active firewalld.service", "active\n", 0)
	expect(t, "firewalld", f.check("NET-001"), Pass)

	f = newFixture(t).cmd("systemctl is-active firewalld.service", "inactive\n", 3).
		file("/etc/ufw/ufw.conf", "ENABLED=yes\n").file("/etc/default/ufw", `DEFAULT_INPUT_POLICY="DROP"`+"\n")
	expect(t, "ufw drop", f.check("NET-001"), Pass)

	f = newFixture(t).file("/etc/ufw/ufw.conf", "ENABLED=yes\n").file("/etc/default/ufw", `DEFAULT_INPUT_POLICY="ACCEPT"`+"\n")
	expect(t, "ufw accept", f.check("NET-001"), Fail)

	f = newFixture(t).cmd("nft list ruleset", "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n", 0)
	expect(t, "nft drop", f.check("NET-001"), Pass)

	f = newFixture(t).cmd("nft list ruleset", "table inet filter {\n chain input {\n  type filter hook input priority 0; policy accept;\n }\n}\n", 0)
	expect(t, "nft accept", f.check("NET-001"), Fail)

	expect(t, "nothing", newFixture(t).check("NET-001"), Fail)
}

func TestUnwantedServices(t *testing.T) {
	f := newFixture(t).dir("/run/systemd/system")
	for _, u := range unwantedUnits {
		f.cmd("systemctl is-active "+u, "inactive\n", 3)
	}
	expect(t, "NET-002", f.check("NET-002"), Pass)

	f.cmd("systemctl is-active cups.service", "active\n", 0)
	r := f.check("NET-002")
	expect(t, "NET-002", r, Fail)
	if !strings.Contains(r.Detail, "cups") {
		t.Errorf("detail: %s", r.Detail)
	}

	expect(t, "no systemd", newFixture(t).check("NET-002"), Skip)

	// systemctl installed but systemd not PID 1 (containers): every unit
	// looks inactive, which must not be read as a pass.
	f = newFixture(t)
	for _, u := range unwantedUnits {
		f.cmd("systemctl is-active "+u, "inactive\n", 3)
	}
	expect(t, "systemctl without systemd", f.check("NET-002"), Skip)
}

// ---- logging & time -----------------------------------------------------------

func TestJournald(t *testing.T) {
	expect(t, "persistent", newFixture(t).file("/etc/systemd/journald.conf", "[Journal]\nStorage=persistent\n").check("LOG-001"), Pass)
	expect(t, "auto with dir", newFixture(t).dir("/var/log/journal").check("LOG-001"), Pass)
	expect(t, "auto no dir", newFixture(t).check("LOG-001"), Fail)
	f := newFixture(t).file("/etc/systemd/journald.conf", "[Journal]\nStorage=persistent\n").
		file("/etc/systemd/journald.conf.d/override.conf", "[Journal]\nStorage=volatile\n")
	expect(t, "drop-in override", f.check("LOG-001"), Fail)
}

func TestTimeSync(t *testing.T) {
	expect(t, "synced", newFixture(t).cmd("timedatectl show", "NTP=yes\nNTPSynchronized=yes\n", 0).check("TIME-001"), Pass)
	expect(t, "disabled", newFixture(t).cmd("timedatectl show", "NTP=no\nNTPSynchronized=no\n", 0).check("TIME-001"), Fail)
	expect(t, "unsynced", newFixture(t).cmd("timedatectl show", "NTP=yes\nNTPSynchronized=no\n", 0).check("TIME-001"), Fail)
	expect(t, "missing", newFixture(t).check("TIME-001"), Error)
}

// ---- updates ------------------------------------------------------------------

func TestAutoUpdatesDebian(t *testing.T) {
	f := newFixture(t).debian().file("/usr/bin/unattended-upgrade", "").
		file("/etc/apt/apt.conf.d/20auto-upgrades", "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n")
	expect(t, "enabled", f.check("UPD-001"), Pass)

	f.file("/etc/apt/apt.conf.d/99-off", "APT::Periodic::Unattended-Upgrade \"0\";\n")
	expect(t, "later file disables", f.check("UPD-001"), Fail)

	expect(t, "not installed", newFixture(t).debian().check("UPD-001"), Fail)
}

func TestAutoUpdatesRHEL(t *testing.T) {
	f := newFixture(t).rhel().cmd("systemctl is-enabled dnf-automatic-install.timer", "enabled\n", 0)
	expect(t, "install timer", f.check("UPD-001"), Pass)

	f = newFixture(t).rhel().cmd("systemctl is-enabled dnf5-automatic.timer", "enabled\n", 0).
		file("/etc/dnf/automatic.conf", "[commands]\napply_updates = yes\n")
	expect(t, "dnf5 apply", f.check("UPD-001"), Pass)

	f = newFixture(t).rhel().cmd("systemctl is-enabled dnf-automatic.timer", "enabled\n", 0).
		file("/etc/dnf/automatic.conf", "[commands]\napply_updates = no\n")
	expect(t, "download only", f.check("UPD-001"), Fail)

	expect(t, "none", newFixture(t).rhel().check("UPD-001"), Fail)
	expect(t, "unknown distro", newFixture(t).check("UPD-001"), Skip)
}

func TestRebootRequired(t *testing.T) {
	expect(t, "debian clean", newFixture(t).debian().check("UPD-002"), Pass)
	expect(t, "debian pending", newFixture(t).debian().file("/run/reboot-required", "").check("UPD-002"), Fail)

	q := "rpm -q --qf %{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\\n "
	rpmOut := "1729781421 6.11.4-301.fc41.x86_64\n1770766569 6.17.10-100.fc41.x86_64\n"

	f := newFixture(t).rhel().file("/proc/sys/kernel/osrelease", "6.17.10-100.fc41.x86_64\n").cmd(q+"kernel-core", rpmOut, 0)
	expect(t, "rhel current", f.check("UPD-002"), Pass)

	f = newFixture(t).rhel().file("/proc/sys/kernel/osrelease", "6.11.4-301.fc41.x86_64\n").cmd(q+"kernel-core", rpmOut, 0)
	expect(t, "rhel stale", f.check("UPD-002"), Fail)

	f = newFixture(t).rhel().cmd(q+"kernel-core", "package kernel-core is not installed\n", 1).
		cmd(q+"kernel", "package kernel is not installed\n", 1)
	expect(t, "rhel no kernel pkg", f.check("UPD-002"), Skip)

	expect(t, "rhel no rpm", newFixture(t).rhel().check("UPD-002"), Error)
}

// ---- framework ----------------------------------------------------------------

func TestRegistryMetadata(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c.ID] {
			t.Errorf("duplicate ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Category == "" || c.Remediation == "" || c.Severity == 0 {
			t.Errorf("%s: incomplete metadata %+v", c.ID, c)
		}
		if !strings.HasPrefix(c.Control, "A.") {
			t.Errorf("%s: control %q is not an Annex A reference", c.ID, c.Control)
		}
	}
	if len(seen) < 40 {
		t.Errorf("only %d checks registered", len(seen))
	}
}

func TestEveryCheckSurvivesEmptyHost(t *testing.T) {
	// An empty filesystem with no commands must never panic or hang; every
	// check must return one of the four statuses.
	h := newFixture(t).host()
	for _, c := range All() {
		r := c.Run(context.Background(), h)
		switch r.Status {
		case Pass, Fail, Skip, Error:
		default:
			t.Errorf("%s returned status %q", c.ID, r.Status)
		}
		if strings.Contains(r.Detail, "internal error") {
			t.Errorf("%s panicked: %s", c.ID, r.Detail)
		}
	}
}

func TestRunRecoversPanics(t *testing.T) {
	c := Check{ID: "X", run: func(context.Context, *platformHost) Result { panic("boom") }}
	r := c.Run(context.Background(), newFixture(t).host())
	if r.Status != Error || !strings.Contains(r.Detail, "boom") {
		t.Fatalf("got %+v", r)
	}
}

func TestRunHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	c := Check{ID: "X", run: func(context.Context, *platformHost) Result { called = true; return Result{Status: Pass} }}
	if r := c.Run(ctx, newFixture(t).host()); r.Status != Error || called {
		t.Fatalf("got %+v called=%v", r, called)
	}
}
