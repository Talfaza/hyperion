package checks

import (
	"context"
	"errors"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

func checkJournald(_ context.Context, h *platform.Host) Result {
	files := []string{"/etc/systemd/journald.conf"}
	for _, dir := range []string{"/usr/lib/systemd/journald.conf.d", "/etc/systemd/journald.conf.d"} {
		if extra, err := h.Glob(dir + "/*.conf"); err == nil {
			files = append(files, extra...)
		}
	}
	cfg, _, err := mergeConfigs(h.ReadFile, files)
	if err != nil {
		return errored(err)
	}
	storage := strings.ToLower(cfg["storage"])
	if storage == "" {
		storage = "auto"
	}
	switch storage {
	case "persistent":
		return pass("Storage=persistent")
	case "auto":
		if info, err := h.Stat("/var/log/journal"); err == nil && info.IsDir() {
			return pass("Storage=auto and /var/log/journal exists")
		}
		return fail("Storage=auto but /var/log/journal is missing; logs are lost on reboot")
	}
	return fail("Storage=%s; logs are not kept on disk", storage)
}

func checkTimeSync(ctx context.Context, h *platform.Host) Result {
	res, err := h.Run.Run(ctx, "timedatectl", "show")
	if errors.Is(err, platform.ErrCommandNotFound) {
		return errored(errors.New("timedatectl not available; verify chrony/ntpd manually"))
	}
	if err != nil {
		return errored(err)
	}
	if res.ExitCode != 0 {
		if !systemdRunning(h) {
			return errored(errors.New("systemd is not running; verify chrony/ntpd manually"))
		}
		return errored(errors.New("timedatectl show failed"))
	}
	kv := platform.ParseEnvFile(res.Stdout)
	switch {
	case kv["NTPSynchronized"] == "yes":
		return pass("clock is NTP synchronized")
	case kv["NTP"] == "no":
		return fail("NTP is disabled")
	}
	return fail("NTP is enabled but the clock is not synchronized")
}

func init() {
	register(
		Check{
			ID: "LOG-001", Title: "System journal is persistent", Category: "Logging", Control: "A.8.15", Severity: Medium,
			Remediation: "Set `Storage=persistent` in /etc/systemd/journald.conf and restart systemd-journald",
			run:         checkJournald,
		},
		Check{
			ID: "TIME-001", Title: "Clock is synchronized with NTP", Category: "Logging", Control: "A.8.17", Severity: Medium,
			Remediation: "Enable chrony or systemd-timesyncd: `timedatectl set-ntp true`",
			run:         checkTimeSync,
		},
	)
}
