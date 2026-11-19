package checks

import (
	"context"
	"errors"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

// existsChecked is like Host.Exists but reports permission errors instead of
// treating an unreadable path as missing (/var/lib/aide is root-only).
func existsChecked(h *platform.Host, path string) (bool, error) {
	_, err := h.Lstat(path)
	switch {
	case err == nil:
		return true, nil
	case isNotExist(err):
		return false, nil
	}
	return false, err
}

var (
	aideBinaries  = []string{"/usr/sbin/aide", "/usr/bin/aide"}
	aideDatabases = []string{"/var/lib/aide/aide.db", "/var/lib/aide/aide.db.gz"}
	// Timers shipped by distro packages (Debian/Ubuntu: dailyaidecheck).
	aideTimers = []string{"dailyaidecheck.timer", "aidecheck.timer", "aide-check.timer", "aide.timer"}
	// Cron locations a scheduled AIDE check may live in.
	aideCron = []string{"/etc/crontab", "/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/var/spool/cron/root", "/var/spool/cron/crontabs/root"}
)

// aideScheduled reports where a periodic AIDE check is configured, if anywhere.
func aideScheduled(ctx context.Context, h *platform.Host) string {
	for _, timer := range aideTimers {
		if s, err := unitState(ctx, h, "is-enabled", timer); err == nil && s == "enabled" {
			return timer
		}
	}
	for _, pattern := range aideCron {
		files, _ := h.Glob(pattern)
		for _, f := range files {
			data, err := h.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && line[0] != '#' && strings.Contains(line, "aide") {
					return f
				}
			}
		}
	}
	return ""
}

func checkFIM(ctx context.Context, h *platform.Host) Result {
	installed := false
	for _, b := range aideBinaries {
		if h.Exists(b) {
			installed = true
		}
	}
	if !installed {
		return fail("AIDE (file integrity monitoring) is not installed")
	}

	initialized := false
	for _, db := range aideDatabases {
		ok, err := existsChecked(h, db)
		if err != nil {
			return errored(err)
		}
		initialized = initialized || ok
	}
	if !initialized {
		return fail("AIDE is installed but its database is not initialized, so nothing is compared")
	}

	where := aideScheduled(ctx, h)
	if where == "" {
		return fail("AIDE database exists but no periodic check is scheduled (cron or systemd timer)")
	}
	return pass("AIDE database initialized; periodic check scheduled in %s", where)
}

// ---- auditd -----------------------------------------------------------------

// auditWatchedPaths must each appear in a loaded audit rule.
var auditWatchedPaths = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config"}

func auditdRunning(ctx context.Context, h *platform.Host) (bool, error) {
	if systemdRunning(h) {
		s, err := unitState(ctx, h, "is-active", "auditd.service")
		if err != nil {
			return false, err
		}
		return s == "active", nil
	}
	return h.Exists("/run/auditd.pid") || h.Exists("/var/run/auditd.pid"), nil
}

// auditRules returns the loaded rules (`auditctl -l`, root only), falling
// back to the rule files when auditctl cannot be used.
func auditRules(ctx context.Context, h *platform.Host) (rules, source string, err error) {
	res, runErr := h.Run.Run(ctx, "auditctl", "-l")
	if runErr == nil && res.ExitCode == 0 {
		return string(res.Stdout), "loaded rules", nil
	}
	files, _ := h.Glob("/etc/audit/rules.d/*.rules")
	files = append(files, "/etc/audit/audit.rules")
	var b strings.Builder
	read := 0
	for _, f := range files {
		data, err := h.ReadFile(f)
		if isNotExist(err) {
			continue
		}
		if err != nil {
			return "", "", err
		}
		read++
		b.Write(data)
		b.WriteByte('\n')
	}
	if read == 0 && runErr != nil {
		return "", "", errors.New("cannot read audit rules (auditctl unavailable, no rule files)")
	}
	return b.String(), "rule files", nil
}

func checkAuditd(ctx context.Context, h *platform.Host) Result {
	if !h.Exists("/usr/sbin/auditd") && !h.Exists("/sbin/auditd") {
		return fail("auditd is not installed")
	}
	running, err := auditdRunning(ctx, h)
	if err != nil {
		return errored(err)
	}
	if !running {
		return fail("auditd is installed but not running")
	}
	rules, source, err := auditRules(ctx, h)
	if err != nil {
		return errored(err)
	}

	var missing []string
	for _, p := range auditWatchedPaths {
		if !strings.Contains(rules, p) {
			missing = append(missing, p)
		}
	}
	rootExec := false
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && line[0] != '#' && strings.Contains(line, "execve") && strings.Contains(line, "euid=0") {
			rootExec = true
		}
	}
	if !rootExec {
		missing = append(missing, "commands run as root (execve, euid=0)")
	}
	if len(missing) > 0 {
		return fail("auditd is running but its %s don't cover: %s", source, strings.Join(missing, ", "))
	}
	return pass("auditd running; %s watch identity files, sudoers and sshd_config and log root commands", source)
}

func init() {
	register(
		Check{
			ID: "FIM-001", Title: "File integrity monitoring is active", Category: "Integrity", Control: "A.8.7", Severity: Medium,
			Remediation: "Install AIDE, initialize its database (`aideinit` on Debian/Ubuntu, `aide --init` elsewhere) and schedule `aide --check` daily (cron or systemd timer)",
			NeedsRoot:   true,
			run:         checkFIM,
		},
		Check{
			ID: "LOG-002", Title: "auditd records identity, sudo and root activity", Category: "Logging", Control: "A.8.15", Severity: Medium,
			Remediation: "Install and enable auditd, and add rules to /etc/audit/rules.d/: `-w /etc/passwd -p wa`, `-w /etc/shadow -p wa`, `-w /etc/group -p wa`, `-w /etc/sudoers -p wa`, `-w /etc/ssh/sshd_config -p wa`, `-a always,exit -F arch=b64 -S execve -F euid=0`; load with `augenrules --load`",
			NeedsRoot:   true,
			run:         checkAuditd,
		},
	)
}
