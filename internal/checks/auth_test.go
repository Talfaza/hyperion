package checks

import (
	"strings"
	"testing"
)

func TestSudoTimeout(t *testing.T) {
	cases := []struct {
		name    string
		sudoers string
		want    Status
	}{
		{"default", "root ALL=(ALL) ALL\n", Pass},
		{"explicit 5", "Defaults timestamp_timeout=5\n", Pass},
		{"zero", "Defaults env_reset, timestamp_timeout=0\n", Pass},
		{"too long", "Defaults timestamp_timeout=15\n", Fail},
		{"never expires", "Defaults timestamp_timeout=-1\n", Fail},
		{"scoped user", "Defaults:alice timestamp_timeout=30\n", Fail},
		{"garbage", "Defaults timestamp_timeout=abc\n", Fail},
		{"continuation", "Defaults env_reset, \\\n  timestamp_timeout=20\n", Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t).fileMode("/etc/sudoers", c.sudoers, 0o440)
			expect(t, "AUTH-001", f.check("AUTH-001"), c.want)
		})
	}
}

func TestSudoIncludes(t *testing.T) {
	f := newFixture(t).
		fileMode("/etc/sudoers", "root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n#include extra\n", 0o440).
		fileMode("/etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD:ALL\n", 0o440).
		// sudo ignores files with a dot or trailing ~, so these must not count.
		fileMode("/etc/sudoers.d/README.txt", "Defaults timestamp_timeout=99\n", 0o440).
		fileMode("/etc/sudoers.d/old~", "Defaults timestamp_timeout=99\n", 0o440).
		fileMode("/etc/extra", "Defaults timestamp_timeout=10\n", 0o440)

	r := f.check("AUTH-002")
	expect(t, "AUTH-002", r, Fail)
	if !strings.Contains(r.Detail, "90-cloud") {
		t.Errorf("AUTH-002 should name the file: %s", r.Detail)
	}
	r = f.check("AUTH-001")
	expect(t, "AUTH-001", r, Fail)
	if !strings.Contains(r.Detail, "10 min") {
		t.Errorf("AUTH-001 should report the relative #include value (10), not ignored files (99): %s", r.Detail)
	}
}

func TestSudoNotAuthenticate(t *testing.T) {
	f := newFixture(t).fileMode("/etc/sudoers", "Defaults !authenticate\n", 0o440)
	expect(t, "AUTH-002", f.check("AUTH-002"), Fail)
	f = newFixture(t).fileMode("/etc/sudoers", "%wheel ALL=(ALL) ALL\n", 0o440)
	expect(t, "AUTH-002", f.check("AUTH-002"), Pass)
}

func TestSudoMissingSkips(t *testing.T) {
	expect(t, "AUTH-001", newFixture(t).check("AUTH-001"), Skip)
}

func TestSudoIncludeLoopIsBounded(t *testing.T) {
	f := newFixture(t).fileMode("/etc/sudoers", "@include /etc/sudoers\n", 0o440)
	expect(t, "AUTH-001", f.check("AUTH-001"), Error)
}

const goodPwquality = "minlen = 14\ndcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n"

func TestPwquality(t *testing.T) {
	pam := "password requisite pam_pwquality.so retry=3\n"

	f := newFixture(t).file("/etc/security/pwquality.conf", goodPwquality).file("/etc/pam.d/common-password", pam)
	expect(t, "AUTH-003", f.check("AUTH-003"), Pass)

	f = newFixture(t).file("/etc/security/pwquality.conf", goodPwquality)
	expect(t, "AUTH-003", f.check("AUTH-003"), Fail) // not wired into PAM

	f = newFixture(t).
		file("/etc/security/pwquality.conf", goodPwquality).
		file("/etc/security/pwquality.conf.d/50-weak.conf", "minlen = 8\n").
		file("/etc/pam.d/system-auth", pam)
	r := f.check("AUTH-003")
	expect(t, "AUTH-003", r, Fail) // drop-in overrides main file
	if !strings.Contains(r.Detail, "minlen=8") {
		t.Errorf("detail: %s", r.Detail)
	}

	expect(t, "AUTH-003", newFixture(t).check("AUTH-003"), Fail)
}

func TestDefaultInactive(t *testing.T) {
	cases := map[string]Status{"INACTIVE=30\n": Pass, "INACTIVE=7\n": Pass, "INACTIVE=-1\n": Fail, "INACTIVE=90\n": Fail, "SHELL=/bin/sh\n": Fail}
	for content, want := range cases {
		f := newFixture(t).file("/etc/default/useradd", content)
		expect(t, "AUTH-004 "+content, f.check("AUTH-004"), want)
	}
	expect(t, "AUTH-004 missing", newFixture(t).check("AUTH-004"), Fail)
}

func TestShadowChecks(t *testing.T) {
	shadow := strings.Join([]string{
		"root:$6$abc:19000:0:99999:7:30::",
		"daemon:*:19000:0:99999:7:::",
		"locked:!$6$x:19000:0:99999:7:::",
		"alice:$y$j9T$abc:19000:0:99999:7:::",
		"ghost::19000:0:99999:7:::",
		"short",
	}, "\n")
	f := newFixture(t).fileMode("/etc/shadow", shadow, 0o640)

	r := f.check("AUTH-005")
	expect(t, "AUTH-005", r, Fail)
	if !strings.Contains(r.Detail, "alice") || strings.Contains(r.Detail, "root") || strings.Contains(r.Detail, "locked") {
		t.Errorf("AUTH-005 should list only alice: %s", r.Detail)
	}

	r = f.check("AUTH-006")
	expect(t, "AUTH-006", r, Fail)
	if !strings.Contains(r.Detail, "ghost") {
		t.Errorf("AUTH-006 should list ghost: %s", r.Detail)
	}

	f = newFixture(t).fileMode("/etc/shadow", "root:$6$abc:19000:0:99999:7:30::\nbin:*:1::::::\n", 0o640)
	expect(t, "AUTH-005", f.check("AUTH-005"), Pass)
	expect(t, "AUTH-006", f.check("AUTH-006"), Pass)
}

func TestUID0(t *testing.T) {
	ok := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
	expect(t, "AUTH-007", newFixture(t).file("/etc/passwd", ok).check("AUTH-007"), Pass)

	bad := ok + "toor:x:0:0::/root:/bin/sh\n"
	r := newFixture(t).file("/etc/passwd", bad).check("AUTH-007")
	expect(t, "AUTH-007", r, Fail)
	if !strings.Contains(r.Detail, "toor") {
		t.Errorf("detail: %s", r.Detail)
	}
}

func FuzzSudoParsers(f *testing.F) {
	f.Add("Defaults:alice timestamp_timeout=30, !authenticate\n@includedir /etc/sudoers.d\nx \\\n")
	f.Fuzz(func(t *testing.T, s string) {
		var lines []sudoLine
		for _, l := range sudoLogicalLines([]byte(s)) {
			_, _ = sudoInclude(l)
			_ = sudoDefaultsOptions(l)
			lines = append(lines, sudoLine{file: "f", text: l})
		}
		_ = evalSudoTimeout(lines)
		_ = evalSudoReauth(lines)
	})
}

func FuzzParseKeyValue(f *testing.F) {
	f.Add("minlen = 14\n[section]\nkey value more\n=\n")
	f.Fuzz(func(t *testing.T, s string) {
		_ = parseKeyValue([]byte(s))
	})
}
