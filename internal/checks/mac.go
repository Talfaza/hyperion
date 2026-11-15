package checks

import (
	"context"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

func selinuxEnforcing(h *platform.Host) (bool, bool) {
	data, err := h.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(data)) == "1", true
}

// apparmorState returns whether AppArmor is enabled and, when the profile
// list is readable (root only), how many profiles are in enforce mode.
func apparmorState(h *platform.Host) (enabled bool, enforcing int, profilesKnown bool) {
	data, err := h.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil || strings.TrimSpace(string(data)) != "Y" {
		return false, 0, false
	}
	profiles, err := h.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return true, 0, false
	}
	return true, strings.Count(string(profiles), "(enforce)"), true
}

func checkMAC(_ context.Context, h *platform.Host) Result {
	enforcing, present := selinuxEnforcing(h)
	if enforcing {
		return pass("SELinux is enforcing")
	}

	aaEnabled, aaEnforcing, aaKnown := apparmorState(h)
	if aaEnabled {
		switch {
		case !aaKnown:
			return pass("AppArmor is enabled (profile modes need root to verify)")
		case aaEnforcing > 0:
			return pass("AppArmor is enabled with %d profiles enforcing", aaEnforcing)
		default:
			return fail("AppArmor is enabled but no profiles are in enforce mode")
		}
	}

	if present {
		return fail("SELinux is in permissive mode")
	}
	if h.OS.Family == platform.FamilyRHEL {
		return fail("SELinux is disabled")
	}
	return fail("no mandatory access control (SELinux or AppArmor) is active")
}

func init() {
	register(Check{
		ID: "MAC-001", Title: "Mandatory access control is enforcing", Category: "Kernel", Control: "A.8.9", Severity: High,
		Remediation: "RHEL family: set SELINUX=enforcing in /etc/selinux/config. Debian/Ubuntu: enable AppArmor and run `aa-enforce /etc/apparmor.d/*`",
		run:         checkMAC,
	})
}
