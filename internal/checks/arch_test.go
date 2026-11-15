package checks

import (
	"strings"
	"testing"
)

func TestArchAutoUpdatesSkips(t *testing.T) {
	r := newFixture(t).arch().check("UPD-001")
	expect(t, "UPD-001", r, Skip)
	if !strings.Contains(r.Detail, "pacman -Syu") {
		t.Errorf("detail should advise pacman -Syu: %s", r.Detail)
	}
}

func TestArchRebootRequired(t *testing.T) {
	const kernel = "6.12.4-arch1-1\n"
	f := newFixture(t).arch().file("/proc/sys/kernel/osrelease", kernel).dir("/usr/lib/modules/6.12.4-arch1-1")
	expect(t, "current kernel", f.check("UPD-002"), Pass)

	// pacman installed 6.12.5 and removed 6.12.4's modules; still running 6.12.4.
	f = newFixture(t).arch().file("/proc/sys/kernel/osrelease", kernel).dir("/usr/lib/modules/6.12.5-arch1-1")
	expect(t, "replaced kernel", f.check("UPD-002"), Fail)

	expect(t, "container", newFixture(t).arch().file("/proc/sys/kernel/osrelease", kernel).check("UPD-002"), Skip)
	expect(t, "unknown kernel", newFixture(t).arch().dir("/usr/lib/modules").check("UPD-002"), Error)
}

func TestPwqualityIgnoresCommentedPAMLines(t *testing.T) {
	commented := "#password required pam_pwquality.so retry=3\npassword required pam_unix.so sha512 shadow\n"
	f := newFixture(t).file("/etc/security/pwquality.conf", goodPwquality).file("/etc/pam.d/passwd", commented)
	r := f.check("AUTH-003")
	expect(t, "AUTH-003 commented", r, Fail)
	if !strings.Contains(r.Detail, "PAM") {
		t.Errorf("detail: %s", r.Detail)
	}

	active := "password required pam_pwquality.so retry=3\n" + commented
	f = newFixture(t).file("/etc/security/pwquality.conf", goodPwquality).file("/etc/pam.d/passwd", active)
	expect(t, "AUTH-003 Arch passwd", f.check("AUTH-003"), Pass)
}
