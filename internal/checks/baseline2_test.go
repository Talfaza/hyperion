package checks

import (
	"strings"
	"testing"
)

// ---- SSH-010 to SSH-014 -----------------------------------------------------

const hardenedSSHDExtra = hardenedSSHDT + `clientaliveinterval 300
clientalivecountmax 3
x11forwarding no
allowtcpforwarding no
loglevel VERBOSE
logingracetime 60
`

var sshExtraIDs = []string{"SSH-010", "SSH-011", "SSH-012", "SSH-013", "SSH-014"}

func TestSSHExtraHardenedPasses(t *testing.T) {
	f := newFixture(t).cmd("sshd -T", hardenedSSHDExtra, 0)
	for _, id := range sshExtraIDs {
		expect(t, id, f.check(id), Pass)
	}
}

func TestSSHExtraDefaultsFail(t *testing.T) {
	// OpenSSH defaults as printed by sshd -T.
	defaults := hardenedSSHDT + "clientaliveinterval 0\nclientalivecountmax 3\nx11forwarding yes\nallowtcpforwarding yes\nloglevel INFO\nlogingracetime 120\n"
	f := newFixture(t).cmd("sshd -T", defaults, 0)
	for _, id := range sshExtraIDs {
		expect(t, id, f.check(id), Fail)
	}
	if d := f.check("SSH-010").Detail; !strings.Contains(d, "never disconnects") {
		t.Errorf("SSH-010 should explain interval 0: %s", d)
	}
}

func TestSSHExtraMatchBlocks(t *testing.T) {
	f := newFixture(t).cmd("sshd -T", hardenedSSHDExtra, 0).
		file("/etc/ssh/sshd_config", hardenedConfigFile+"Match User dev\n    AllowTcpForwarding yes\n    ClientAliveInterval 0\n    LogLevel QUIET\n")
	for _, id := range []string{"SSH-010", "SSH-012", "SSH-013"} {
		r := f.check(id)
		expect(t, id, r, Fail)
		if !strings.Contains(r.Detail, "Match User dev") {
			t.Errorf("%s should name the Match block: %s", id, r.Detail)
		}
	}
	expect(t, "SSH-011", f.check("SSH-011"), Pass)
}

func TestSSHExtraFallbackTimeUnits(t *testing.T) {
	// Not root: values come from the files, which may use time units.
	base := "ClientAliveInterval 5m\nClientAliveCountMax 2\nX11Forwarding no\nAllowTcpForwarding no\nLogLevel verbose\n"
	f := newFixture(t).user().file("/etc/ssh/sshd_config", base+"LoginGraceTime 1m\n")
	expect(t, "SSH-010 5m", f.check("SSH-010"), Pass)
	expect(t, "SSH-013 lowercase", f.check("SSH-013"), Pass)
	expect(t, "SSH-014 1m", f.check("SSH-014"), Pass)

	f = newFixture(t).user().file("/etc/ssh/sshd_config", base+"LoginGraceTime 2m\n")
	expect(t, "SSH-014 2m", f.check("SSH-014"), Fail)
	f = newFixture(t).user().file("/etc/ssh/sshd_config", base+"LoginGraceTime 0\n")
	expect(t, "SSH-014 unlimited", f.check("SSH-014"), Fail)
	// Unset LoginGraceTime defaults to 120 s.
	f = newFixture(t).user().file("/etc/ssh/sshd_config", base)
	expect(t, "SSH-014 default", f.check("SSH-014"), Fail)
}

func TestParseSSHTime(t *testing.T) {
	cases := map[string]int{"60": 60, "1m": 60, "1m30s": 90, "2h": 7200, "1w": 604800, "1d1h1m1s": 90061, "45s": 45, "0": 0}
	for in, want := range cases {
		if got, err := parseSSHTime(in); err != nil || got != want {
			t.Errorf("parseSSHTime(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "m", "1x", "1.5m", "-1", "+5", "99999999999999999999", "9999999999w"} {
		if _, err := parseSSHTime(bad); err == nil {
			t.Errorf("parseSSHTime(%q) accepted invalid input", bad)
		}
	}
}

func FuzzParseSSHTime(f *testing.F) {
	f.Add("1d1h1m1s")
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseSSHTime(s) })
}

// ---- FIM-001 ------------------------------------------------------------------

func TestFIM(t *testing.T) {
	expect(t, "not installed", newFixture(t).check("FIM-001"), Fail)

	f := newFixture(t).file("/usr/bin/aide", "")
	r := f.check("FIM-001")
	expect(t, "no database", r, Fail)
	if !strings.Contains(r.Detail, "not initialized") {
		t.Errorf("detail: %s", r.Detail)
	}

	f.file("/var/lib/aide/aide.db.gz", "")
	r = f.check("FIM-001")
	expect(t, "not scheduled", r, Fail)
	if !strings.Contains(r.Detail, "scheduled") {
		t.Errorf("detail: %s", r.Detail)
	}

	expect(t, "cron.d", newFixture(t).file("/usr/sbin/aide", "").file("/var/lib/aide/aide.db", "").
		file("/etc/cron.d/aide", "0 5 * * * root /usr/sbin/aide --check\n").check("FIM-001"), Pass)
	expect(t, "debian timer", newFixture(t).file("/usr/bin/aide", "").file("/var/lib/aide/aide.db", "").
		cmd("systemctl is-enabled dailyaidecheck.timer", "enabled\n", 0).check("FIM-001"), Pass)
	expect(t, "commented cron", newFixture(t).file("/usr/bin/aide", "").file("/var/lib/aide/aide.db", "").
		file("/etc/crontab", "# 0 5 * * * root aide --check\n").check("FIM-001"), Fail)
}

// ---- LOG-002 ------------------------------------------------------------------

const goodAuditRules = `-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S execve -F euid=0 -F key=rootcmd
`

func TestAuditd(t *testing.T) {
	expect(t, "not installed", newFixture(t).check("LOG-002"), Fail)

	f := newFixture(t).file("/usr/sbin/auditd", "").dir("/run/systemd/system").
		cmd("systemctl is-active auditd.service", "inactive\n", 3)
	r := f.check("LOG-002")
	expect(t, "stopped", r, Fail)
	if !strings.Contains(r.Detail, "not running") {
		t.Errorf("detail: %s", r.Detail)
	}

	running := func() *fixture {
		return newFixture(t).file("/usr/sbin/auditd", "").dir("/run/systemd/system").
			cmd("systemctl is-active auditd.service", "active\n", 0)
	}
	expect(t, "full rules", running().cmd("auditctl -l", goodAuditRules, 0).check("LOG-002"), Pass)

	r = running().cmd("auditctl -l", "No rules\n", 0).check("LOG-002")
	expect(t, "no rules", r, Fail)
	if !strings.Contains(r.Detail, "/etc/shadow") || !strings.Contains(r.Detail, "euid=0") {
		t.Errorf("detail should list what is missing: %s", r.Detail)
	}

	// auditctl unavailable: fall back to the rule files.
	r = running().file("/etc/audit/rules.d/hyperion.rules", goodAuditRules).check("LOG-002")
	expect(t, "rule files", r, Pass)
	if !strings.Contains(r.Detail, "rule files") {
		t.Errorf("detail should say where rules came from: %s", r.Detail)
	}

	// Without systemd, a pid file shows auditd is running.
	expect(t, "pid file", newFixture(t).file("/usr/sbin/auditd", "").file("/run/auditd.pid", "1\n").
		cmd("auditctl -l", goodAuditRules, 0).check("LOG-002"), Pass)

	// A commented-out execve rule doesn't count.
	commented := strings.Replace(goodAuditRules, "-a always", "#-a always", 1)
	expect(t, "commented execve", running().cmd("auditctl -l", commented, 0).check("LOG-002"), Fail)
}

// ---- CRY-001 / CRY-002 --------------------------------------------------------

func TestRootEncryption(t *testing.T) {
	mounts := func(src string) string { return src + " / ext4 rw 0 0\n" }

	expect(t, "container", newFixture(t).file("/proc/self/mounts", "overlay / overlay rw 0 0\n").check("CRY-001"), Skip)

	f := newFixture(t).file("/proc/self/mounts", mounts("/dev/vda1")).dir("/sys/class/block/vda1")
	expect(t, "plain partition", f.check("CRY-001"), Fail)

	f = newFixture(t).file("/proc/self/mounts", mounts("/dev/mapper/luks-abc")).
		symlink("/dev/mapper/luks-abc", "../dm-0").
		file("/sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-luks-abc\n")
	expect(t, "LUKS", f.check("CRY-001"), Pass)

	// LVM on LUKS: the root LV (dm-1) sits on the LUKS mapping (dm-0).
	f = newFixture(t).file("/proc/self/mounts", mounts("/dev/mapper/vg-root")).
		symlink("/dev/mapper/vg-root", "../dm-1").
		file("/sys/class/block/dm-1/dm/uuid", "LVM-xyz\n").
		dir("/sys/class/block/dm-1/slaves/dm-0").
		file("/sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc\n")
	expect(t, "LVM on LUKS", f.check("CRY-001"), Pass)

	// LVM without encryption.
	f = newFixture(t).file("/proc/self/mounts", mounts("/dev/mapper/vg-root")).
		symlink("/dev/mapper/vg-root", "../dm-1").
		file("/sys/class/block/dm-1/dm/uuid", "LVM-xyz\n").
		dir("/sys/class/block/dm-1/slaves/sda2").dir("/sys/class/block/sda2")
	expect(t, "plain LVM", f.check("CRY-001"), Fail)

	expect(t, "unmappable", newFixture(t).file("/proc/self/mounts", mounts("/dev/root")).check("CRY-001"), Error)
}

func TestSwapEncryption(t *testing.T) {
	const header = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
	plainRoot := "/dev/vda1 / ext4 rw 0 0\n"

	expect(t, "no swap", newFixture(t).file("/proc/swaps", header).file("/proc/self/mounts", plainRoot).check("CRY-002"), Pass)
	expect(t, "zram", newFixture(t).file("/proc/swaps", header+"/dev/zram0 partition 8G 0 100\n").
		file("/proc/self/mounts", plainRoot).check("CRY-002"), Pass)

	r := newFixture(t).file("/proc/swaps", header+"/dev/vda2 partition 2G 0 -2\n").
		file("/proc/self/mounts", plainRoot).dir("/sys/class/block/vda2").check("CRY-002")
	expect(t, "plain partition", r, Fail)
	if !strings.Contains(r.Detail, "/dev/vda2") {
		t.Errorf("detail: %s", r.Detail)
	}

	expect(t, "crypt partition", newFixture(t).file("/proc/swaps", header+"/dev/dm-2 partition 2G 0 -2\n").
		file("/proc/self/mounts", plainRoot).file("/sys/class/block/dm-2/dm/uuid", "CRYPT-PLAIN-swap\n").check("CRY-002"), Pass)

	// Swap files are as safe as the filesystem they live on.
	encRoot := newFixture(t).file("/proc/swaps", header+"/swapfile file 1G 0 -2\n").
		file("/proc/self/mounts", "/dev/mapper/luks-abc / ext4 rw 0 0\n").
		symlink("/dev/mapper/luks-abc", "../dm-0").file("/sys/class/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc\n")
	expect(t, "swapfile on LUKS", encRoot.check("CRY-002"), Pass)
	expect(t, "swapfile on plain", newFixture(t).file("/proc/swaps", header+"/swapfile file 1G 0 -2\n").
		file("/proc/self/mounts", plainRoot).dir("/sys/class/block/vda1").check("CRY-002"), Fail)
}
