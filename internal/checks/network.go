package checks

import (
	"context"
	"errors"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

// errSystemdNotRunning means systemctl exists but systemd is not PID 1
// (containers, chroots). `systemctl is-active` then reports every unit as not
// active, which must not be mistaken for "the service is stopped".
var errSystemdNotRunning = errors.New("systemd is not running")

// systemdRunning is sd_booted(3): systemd creates /run/systemd/system at boot.
func systemdRunning(h *platform.Host) bool {
	return h.Exists("/run/systemd/system")
}

// unitState returns `systemctl is-active` or `is-enabled` output for one unit.
// is-enabled reads unit files and works offline; is-active needs a running
// systemd and returns errSystemdNotRunning without one.
func unitState(ctx context.Context, h *platform.Host, verb, unit string) (string, error) {
	if verb == "is-active" && !systemdRunning(h) {
		return "", errSystemdNotRunning
	}
	res, err := h.Run.Run(ctx, "systemctl", verb, unit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(res.Stdout)), nil
}

// nftHasDefaultDrop looks for a base chain on the input hook with policy drop.
func nftHasDefaultDrop(ruleset string) bool {
	for _, line := range strings.Split(ruleset, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "hook input") && strings.Contains(line, "policy drop") {
			return true
		}
	}
	return false
}

func checkFirewall(ctx context.Context, h *platform.Host) Result {
	if s, err := unitState(ctx, h, "is-active", "firewalld.service"); err == nil && s == "active" {
		return pass("firewalld is active")
	}

	if data, err := h.ReadFile("/etc/ufw/ufw.conf"); err == nil && platform.ParseEnvFile(data)["ENABLED"] == "yes" {
		def, err := h.ReadFile("/etc/default/ufw")
		if err != nil {
			return errored(err)
		}
		policy := platform.ParseEnvFile(def)["DEFAULT_INPUT_POLICY"]
		if policy == "DROP" || policy == "REJECT" {
			return pass("ufw is enabled with default %s on incoming", strings.ToLower(policy))
		}
		return fail("ufw is enabled but the default incoming policy is %s", orUnset(policy))
	}

	res, err := h.Run.Run(ctx, "nft", "list", "ruleset")
	switch {
	case errors.Is(err, platform.ErrCommandNotFound):
		return fail("no active firewall found (firewalld, ufw, nftables)")
	case err != nil:
		return errored(err)
	case res.ExitCode != 0:
		if !h.IsRoot {
			return errored(errors.New("cannot read nftables ruleset"))
		}
		return errored(errors.New("nft list ruleset failed"))
	case nftHasDefaultDrop(string(res.Stdout)):
		return pass("nftables input chain has a default drop policy")
	}
	return fail("no default-deny firewall found (firewalld, ufw, nftables)")
}

var unwantedUnits = []string{
	"avahi-daemon.service",
	"cups.service",
	"rpcbind.service",
	"telnet.socket",
	"rsh.socket",
	"xinetd.service",
	"vsftpd.service",
}

func checkUnwantedServices(ctx context.Context, h *platform.Host) Result {
	var running []string
	for _, unit := range unwantedUnits {
		s, err := unitState(ctx, h, "is-active", unit)
		if errors.Is(err, platform.ErrCommandNotFound) || errors.Is(err, errSystemdNotRunning) {
			return skip("systemd is not running; cannot see which services are active")
		}
		if err != nil {
			return errored(err)
		}
		if s == "active" {
			running = append(running, unit)
		}
	}
	if len(running) > 0 {
		return fail("unneeded services running: %s", strings.Join(running, ", "))
	}
	return pass("none of the known unneeded services are running")
}

func init() {
	register(
		Check{
			ID: "NET-001", Title: "Host firewall is active with default deny", Category: "Network", Control: "A.8.9", Severity: High,
			Remediation: "Enable firewalld, `ufw default deny incoming && ufw enable`, or an nftables input chain with `policy drop`",
			NeedsRoot:   true,
			run:         checkFirewall,
		},
		Check{
			ID: "NET-002", Title: "Unneeded network services are disabled", Category: "Network", Control: "A.8.9", Severity: Medium,
			Remediation: "Run `systemctl disable --now <unit>` for each listed unit, or remove the package",
			run:         checkUnwantedServices,
		},
	)
}
