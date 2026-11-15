package checks

import (
	"context"
	"strconv"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

type mountEntry struct {
	point   string
	fstype  string
	options map[string]bool
}

// parseMounts parses /proc/self/mounts. Later entries for the same mount
// point shadow earlier ones (over-mounts), so the last match wins.
func parseMounts(data []byte) map[string]mountEntry {
	out := map[string]mountEntry{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		opts := map[string]bool{}
		for _, o := range strings.Split(f[3], ",") {
			opts[o] = true
		}
		point := unescapeMount(f[1])
		out[point] = mountEntry{point: point, fstype: f[2], options: opts}
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for space etc.) the kernel
// uses in /proc/self/mounts.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func mountCheck(c Check, point string, required ...string) Check {
	c.Category = "Mounts"
	c.run = func(_ context.Context, h *platform.Host) Result {
		data, err := h.ReadFile("/proc/self/mounts")
		if err != nil {
			return errored(err)
		}
		m, ok := parseMounts(data)[point]
		if !ok {
			return fail("%s is not a separate mount", point)
		}
		var missing []string
		for _, opt := range required {
			if !m.options[opt] {
				missing = append(missing, opt)
			}
		}
		if len(missing) > 0 {
			return fail("%s (%s) is missing %s", point, m.fstype, strings.Join(missing, ","))
		}
		return pass("%s mounted with %s", point, strings.Join(required, ","))
	}
	return c
}

func init() {
	register(
		mountCheck(Check{
			ID: "MNT-001", Title: "/tmp is mounted noexec,nosuid,nodev", Control: "A.8.9", Severity: Medium,
			Remediation: "Mount /tmp with `defaults,noexec,nosuid,nodev` (fstab entry or tmp.mount override)",
		}, "/tmp", "noexec", "nosuid", "nodev"),
		mountCheck(Check{
			ID: "MNT-002", Title: "/var/tmp is mounted noexec,nosuid,nodev", Control: "A.8.9", Severity: Medium,
			Remediation: "Mount /var/tmp with `defaults,noexec,nosuid,nodev` in /etc/fstab",
		}, "/var/tmp", "noexec", "nosuid", "nodev"),
		mountCheck(Check{
			ID: "MNT-003", Title: "/dev/shm is mounted noexec,nosuid,nodev", Control: "A.8.9", Severity: Medium,
			Remediation: "Add `tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0` to /etc/fstab",
		}, "/dev/shm", "noexec", "nosuid", "nodev"),
		mountCheck(Check{
			ID: "MNT-004", Title: "/var is mounted nosuid,nodev", Control: "A.8.9", Severity: Low,
			Remediation: "Mount /var with `defaults,nosuid,nodev` (never noexec: it breaks package managers and containers)",
		}, "/var", "nosuid", "nodev"),
		mountCheck(Check{
			ID: "MNT-005", Title: "/home is mounted nosuid,nodev", Control: "A.8.9", Severity: Low,
			Remediation: "Mount /home with `defaults,nosuid,nodev` in /etc/fstab",
		}, "/home", "nosuid", "nodev"),
	)
}
