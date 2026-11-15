package checks

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

var aptUnattendedRe = regexp.MustCompile(`APT::Periodic::Unattended-Upgrade\s+"([0-9]+)"`)

func checkAutoUpdatesDebian(h *platform.Host) Result {
	if !h.Exists("/usr/bin/unattended-upgrade") {
		return fail("unattended-upgrades is not installed")
	}
	files, err := h.Glob("/etc/apt/apt.conf.d/*")
	if err != nil {
		return errored(err)
	}
	enabled := false
	for _, f := range files {
		data, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		// Later files override earlier ones, as with apt itself.
		for _, m := range aptUnattendedRe.FindAllStringSubmatch(string(data), -1) {
			enabled = m[1] != "0"
		}
	}
	if enabled {
		return pass("unattended-upgrades is enabled")
	}
	return fail("unattended-upgrades is installed but APT::Periodic::Unattended-Upgrade is not enabled")
}

func checkAutoUpdatesRHEL(ctx context.Context, h *platform.Host) Result {
	if s, err := unitState(ctx, h, "is-enabled", "dnf-automatic-install.timer"); err == nil && s == "enabled" {
		return pass("dnf-automatic-install.timer is enabled")
	}
	for _, timer := range []string{"dnf5-automatic.timer", "dnf-automatic.timer"} {
		s, err := unitState(ctx, h, "is-enabled", timer)
		if err != nil || s != "enabled" {
			continue
		}
		data, err := h.ReadFile("/etc/dnf/automatic.conf")
		if err != nil && !isNotExist(err) {
			return errored(err)
		}
		if strings.EqualFold(parseKeyValue(data)["apply_updates"], "yes") {
			return pass("%s is enabled with apply_updates = yes", timer)
		}
		return fail("%s is enabled but only downloads updates (apply_updates != yes)", timer)
	}
	return fail("no dnf-automatic timer is enabled")
}

func checkAutoUpdates(ctx context.Context, h *platform.Host) Result {
	switch h.OS.Family {
	case platform.FamilyDebian:
		return checkAutoUpdatesDebian(h)
	case platform.FamilyRHEL:
		return checkAutoUpdatesRHEL(ctx, h)
	case platform.FamilyArch:
		// Arch updates can need manual intervention, so the distro advises
		// against unattended upgrades. Not applicable rather than failing.
		return skip("Arch does not support unattended upgrades; patch regularly with `pacman -Syu`")
	}
	return skip("unsupported distribution %q", h.OS.ID)
}

var errNoKernelPackage = errors.New("no kernel package found in the rpm database")

// latestInstalledKernel asks the local rpm database (never the network, unlike
// `dnf needs-restarting`) for the most recently installed kernel.
func latestInstalledKernel(ctx context.Context, h *platform.Host) (string, error) {
	for _, pkg := range []string{"kernel-core", "kernel"} {
		res, err := h.Run.Run(ctx, "rpm", "-q", "--qf", `%{INSTALLTIME} %{VERSION}-%{RELEASE}.%{ARCH}\n`, pkg)
		if err != nil {
			return "", err
		}
		if res.ExitCode != 0 {
			continue
		}
		var newest int64 = -1
		var version string
		for _, line := range strings.Split(string(res.Stdout), "\n") {
			ts, ver, ok := strings.Cut(strings.TrimSpace(line), " ")
			if !ok {
				continue
			}
			n, err := strconv.ParseInt(ts, 10, 64)
			if err == nil && n > newest {
				newest, version = n, ver
			}
		}
		if version != "" {
			return version, nil
		}
	}
	return "", errNoKernelPackage
}

// checkRebootRequiredArch relies on pacman deleting the old kernel's modules
// when it installs a new kernel: if the running kernel's module directory is
// gone, the machine is running a replaced kernel and needs a reboot.
func checkRebootRequiredArch(h *platform.Host) Result {
	if !h.Exists("/usr/lib/modules") {
		return skip("no kernel modules installed (container image?)")
	}
	if h.Kernel == "" {
		return errored(errors.New("cannot read the running kernel version"))
	}
	if !h.Exists("/usr/lib/modules/" + h.Kernel) {
		return fail("running kernel %s was replaced by an update; reboot to load the new one", h.Kernel)
	}
	return pass("running kernel %s is still installed", h.Kernel)
}

func checkRebootRequired(ctx context.Context, h *platform.Host) Result {
	switch h.OS.Family {
	case platform.FamilyDebian:
		if h.Exists("/run/reboot-required") || h.Exists("/var/run/reboot-required") {
			return fail("a reboot is required to finish applying updates")
		}
		return pass("no reboot pending")
	case platform.FamilyRHEL:
		latest, err := latestInstalledKernel(ctx, h)
		if errors.Is(err, errNoKernelPackage) {
			return skip("no kernel package installed (container image?)")
		}
		if err != nil {
			return errored(err)
		}
		if latest != h.Kernel {
			return fail("running kernel %s but %s is installed; reboot to load it", h.Kernel, latest)
		}
		return pass("running the newest installed kernel (%s)", latest)
	case platform.FamilyArch:
		return checkRebootRequiredArch(h)
	}
	return skip("unsupported distribution %q", h.OS.ID)
}

func init() {
	register(
		Check{
			ID: "UPD-001", Title: "Automatic security updates are enabled", Category: "Updates", Control: "A.8.8", Severity: High,
			Remediation: "Debian/Ubuntu: install unattended-upgrades and run `dpkg-reconfigure -plow unattended-upgrades`. RHEL family: install dnf-automatic and `systemctl enable --now dnf-automatic-install.timer`",
			run:         checkAutoUpdates,
		},
		Check{
			ID: "UPD-002", Title: "No reboot pending for installed updates", Category: "Updates", Control: "A.8.8", Severity: Medium,
			Remediation: "Schedule a reboot so the patched kernel and libraries are loaded",
			run:         checkRebootRequired,
		},
	)
}
