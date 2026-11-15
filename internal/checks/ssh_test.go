package checks

import (
	"strings"
	"testing"
)

const hardenedSSHDT = `port 22
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
permitemptypasswords no
pubkeyauthentication yes
maxauthtries 3
kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256
ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
`

var sshIDs = []string{"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005", "SSH-006", "SSH-007", "SSH-008", "SSH-009"}

func TestSSHHardenedPassesAll(t *testing.T) {
	f := newFixture(t).cmd("sshd -T", hardenedSSHDT, 0)
	for _, id := range sshIDs {
		expect(t, id, f.check(id), Pass)
	}
}

func TestSSHWeakFailsAll(t *testing.T) {
	weak := `permitrootlogin prohibit-password
passwordauthentication yes
kbdinteractiveauthentication yes
permitemptypasswords yes
pubkeyauthentication no
maxauthtries 6
kexalgorithms curve25519-sha256,diffie-hellman-group14-sha1
ciphers aes256-gcm@openssh.com,aes128-cbc
macs hmac-sha2-256-etm@openssh.com,hmac-sha1
`
	f := newFixture(t).cmd("sshd -T", weak, 0)
	for _, id := range sshIDs {
		expect(t, id, f.check(id), Fail)
	}
	if d := f.check("SSH-007").Detail; !strings.Contains(d, "diffie-hellman-group14-sha1") {
		t.Errorf("SSH-007 detail should name the weak algorithm: %s", d)
	}
}

func TestSSHNotInstalledSkips(t *testing.T) {
	f := newFixture(t)
	for _, id := range sshIDs {
		expect(t, id, f.check(id), Skip)
	}
}

func TestSSHFallbackParsesIncludesFirstValueWins(t *testing.T) {
	// sshd -T unavailable (not registered in the fake runner): parse files.
	f := newFixture(t).
		file("/etc/ssh/sshd_config", `# main config
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin yes
PasswordAuthentication yes
Match User backup
    PasswordAuthentication yes
    PermitRootLogin yes
`).
		file("/etc/ssh/sshd_config.d/10-first.conf", "PermitRootLogin no\nPasswordAuthentication=no\n").
		file("/etc/ssh/sshd_config.d/20-second.conf", "PermitRootLogin yes\nMaxAuthTries 2\n")

	expect(t, "SSH-001", f.check("SSH-001"), Pass) // first value (10-first) wins over later ones
	expect(t, "SSH-002", f.check("SSH-002"), Pass) // key=value syntax
	expect(t, "SSH-005", f.check("SSH-005"), Pass)
	expect(t, "SSH-003", f.check("SSH-003"), Fail) // default kbdinteractive yes
	expect(t, "SSH-007", f.check("SSH-007"), Fail) // unset algorithms are not restricted
}

func TestSSHFallbackRelativeIncludeAndLegacyKeyword(t *testing.T) {
	f := newFixture(t).
		file("/etc/ssh/sshd_config", "Include sshd_config.d/*.conf\n").
		file("/etc/ssh/sshd_config.d/a.conf", "ChallengeResponseAuthentication no\n")
	expect(t, "SSH-003", f.check("SSH-003"), Pass)
}

func TestSSHFallbackIncludeLoopIsBounded(t *testing.T) {
	f := newFixture(t).file("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config\n")
	r := f.check("SSH-001")
	expect(t, "SSH-001", r, Error)
	if !strings.Contains(r.Detail, "nesting") {
		t.Errorf("want include depth error, got %s", r.Detail)
	}
}

func TestSSHAlgorithmModifiersFail(t *testing.T) {
	f := newFixture(t).cmd("sshd -T", "ciphers +aes128-cbc\nkexalgorithms \n", 0)
	r := f.check("SSH-008")
	expect(t, "SSH-008", r, Fail)
	expect(t, "SSH-007", f.check("SSH-007"), Fail)
}

func TestSSHDTestFailureFallsBackToFiles(t *testing.T) {
	f := newFixture(t).
		cmd("sshd -T", "", 255).
		file("/etc/ssh/sshd_config", "PermitRootLogin no\n")
	expect(t, "SSH-001", f.check("SSH-001"), Pass)
}

func TestSplitSSHDLine(t *testing.T) {
	cases := map[string][2]string{
		"PermitRootLogin no":   {"PermitRootLogin", "no"},
		"PermitRootLogin=no":   {"PermitRootLogin", "no"},
		"PermitRootLogin = no": {"PermitRootLogin", "no"},
		"PermitRootLogin\tno":  {"PermitRootLogin", "no"},
		"Ciphers a,b,c":        {"Ciphers", "a,b,c"},
		"Lonely":               {"Lonely", ""},
	}
	for in, want := range cases {
		k, v := splitSSHDLine(in)
		if k != want[0] || v != want[1] {
			t.Errorf("splitSSHDLine(%q) = %q,%q want %q,%q", in, k, v, want[0], want[1])
		}
	}
}

func FuzzSSHDParsers(f *testing.F) {
	f.Add("PermitRootLogin=no\nciphers +a,b\n\x00\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseSSHDTest([]byte(s))
		for _, line := range strings.Split(s, "\n") {
			_, _ = splitSSHDLine(line)
		}
		settings := &sshdSettings{values: parseSSHDTest([]byte(s))}
		for _, key := range []string{"ciphers", "macs", "kexalgorithms"} {
			_ = expectSubset(key, "x")(settings)
		}
	})
}

func TestSSHNotRunningIsNoted(t *testing.T) {
	weak := "permitrootlogin yes\n"
	f := newFixture(t).dir("/run/systemd/system").cmd("sshd -T", weak, 0).
		cmd("systemctl is-active sshd.service", "inactive\n", 3).
		cmd("systemctl is-active ssh.service", "inactive\n", 3)
	r := f.check("SSH-001")
	expect(t, "SSH-001", r, Fail) // still a failure: the config is weak
	if !strings.Contains(r.Detail, "not running") {
		t.Errorf("want not-running note: %s", r.Detail)
	}

	f = newFixture(t).dir("/run/systemd/system").cmd("sshd -T", weak, 0).cmd("systemctl is-active ssh.service", "active\n", 0)
	if r := f.check("SSH-001"); strings.Contains(r.Detail, "not running") {
		t.Errorf("running sshd marked as not running: %s", r.Detail)
	}

	// systemd not running (systemctl answers "inactive"): state unknown, no note.
	f = newFixture(t).cmd("sshd -T", weak, 0).cmd("systemctl is-active sshd.service", "inactive\n", 3)
	if r := f.check("SSH-001"); strings.Contains(r.Detail, "not running") {
		t.Errorf("unknown state softened the finding: %s", r.Detail)
	}
}

func TestSSHDropInSortsFirst(t *testing.T) {
	// sshd is first-value-wins; the recommended drop-in must sort before
	// distro files like 50-redhat.conf and 50-cloud-init.conf.
	base := sshDropIn[strings.LastIndex(sshDropIn, "/")+1:]
	for _, distro := range []string{"50-redhat.conf", "50-cloud-init.conf", "01-permitrootlogin.conf"} {
		if base >= distro {
			t.Errorf("%s does not sort before %s", base, distro)
		}
	}
}
