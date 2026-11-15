package checks

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

const sysctlDropIn = "/etc/sysctl.d/99-hyperion-hardening.conf"

// sysctlPath maps "net.ipv4.ip_forward" to "/proc/sys/net/ipv4/ip_forward".
func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

func readSysctl(h *platform.Host, key string) (string, error) {
	data, err := h.ReadFile(sysctlPath(key))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// containerHost reports signs of Docker/containerd/Kubernetes, which
// legitimately need IP forwarding.
func containerHost(h *platform.Host) bool {
	for _, p := range []string{"/run/docker.sock", "/run/containerd/containerd.sock", "/etc/kubernetes"} {
		if h.Exists(p) {
			return true
		}
	}
	return false
}

type sysctlRule struct {
	id, key, want string
	min           bool // value must be >= want instead of == want
	severity      Severity
	title         string
}

var sysctlRules = []sysctlRule{
	{"KRN-001", "kernel.randomize_va_space", "2", false, High, "Full ASLR is enabled"},
	{"KRN-002", "kernel.dmesg_restrict", "1", false, Low, "Kernel log is restricted to privileged users"},
	{"KRN-003", "kernel.kptr_restrict", "2", false, Medium, "Kernel pointers are hidden"},
	{"KRN-004", "kernel.yama.ptrace_scope", "1", true, Medium, "ptrace is restricted to parent processes"},
	{"KRN-005", "net.ipv4.tcp_syncookies", "1", false, Medium, "TCP SYN cookies are enabled"},
	{"KRN-006", "net.ipv4.ip_forward", "0", false, Medium, "IPv4 forwarding is disabled"},
	{"KRN-007", "net.ipv4.conf.all.accept_redirects", "0", false, Medium, "ICMP redirects are not accepted"},
	{"KRN-008", "net.ipv4.conf.all.send_redirects", "0", false, Medium, "ICMP redirects are not sent"},
	{"KRN-009", "net.ipv4.conf.all.rp_filter", "1", false, Medium, "Strict reverse path filtering is enabled"},
	{"KRN-010", "fs.protected_symlinks", "1", false, Medium, "Symlink protection is enabled"},
	{"KRN-011", "fs.protected_hardlinks", "1", false, Medium, "Hardlink protection is enabled"},
	{"KRN-012", "fs.suid_dumpable", "0", false, Medium, "setuid programs cannot dump core"},
}

func (r sysctlRule) check() Check {
	return Check{
		ID: r.id, Title: r.title, Category: "Kernel", Control: "A.8.9", Severity: r.severity,
		Remediation: fmt.Sprintf("Add `%s = %s` to %s and run `sysctl --system`", r.key, r.want, sysctlDropIn),
		run: func(_ context.Context, h *platform.Host) Result {
			got, err := readSysctl(h, r.key)
			if isNotExist(err) {
				return fail("%s is not available on this kernel", r.key)
			}
			if err != nil {
				return errored(err)
			}
			ok := got == r.want
			if r.min {
				g, err1 := strconv.Atoi(got)
				w, _ := strconv.Atoi(r.want)
				ok = err1 == nil && g >= w
			}
			if ok {
				return pass("%s = %s", r.key, got)
			}
			want := r.want
			if r.min {
				want = "≥ " + want
			}
			res := fail("%s = %s (want %s)", r.key, got, want)
			if r.key == "net.ipv4.ip_forward" && containerHost(h) {
				res.Detail += "; container runtime detected, forwarding may be required: skip with --skip " + r.id
			}
			return res
		},
	}
}

func init() {
	for _, r := range sysctlRules {
		register(r.check())
	}
}
