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

// sysctlRule is one check over one or more sysctl keys that must all hold the
// wanted value. Network rules cover IPv4 and IPv6, and both "all" (every
// existing interface) and "default" (interfaces created later): checking only
// net.ipv4.conf.all would miss new interfaces and the whole IPv6 stack.
type sysctlRule struct {
	id       string
	keys     []string
	want     string
	min      bool // value must be >= want instead of == want
	severity Severity
	title    string
	note     string // appended to the remediation
}

var sysctlRules = []sysctlRule{
	{id: "KRN-001", keys: []string{"kernel.randomize_va_space"}, want: "2", severity: High, title: "Full ASLR is enabled"},
	{id: "KRN-002", keys: []string{"kernel.dmesg_restrict"}, want: "1", severity: Low, title: "Kernel log is restricted to privileged users"},
	{id: "KRN-003", keys: []string{"kernel.kptr_restrict"}, want: "2", severity: Medium, title: "Kernel pointers are hidden"},
	{id: "KRN-004", keys: []string{"kernel.yama.ptrace_scope"}, want: "1", min: true, severity: Medium, title: "ptrace is restricted to parent processes"},
	{id: "KRN-005", keys: []string{"net.ipv4.tcp_syncookies"}, want: "1", severity: Medium, title: "TCP SYN cookies are enabled"},
	{id: "KRN-006", keys: []string{
		"net.ipv4.ip_forward",
		"net.ipv6.conf.all.forwarding",
	}, want: "0", severity: Medium, title: "IP forwarding is disabled (IPv4 and IPv6)"},
	{id: "KRN-007", keys: []string{
		"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects",
		"net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects",
	}, want: "0", severity: Medium, title: "ICMP redirects are not accepted (IPv4 and IPv6)"},
	{id: "KRN-008", keys: []string{
		"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects",
	}, want: "0", severity: Medium, title: "ICMP redirects are not sent"},
	{id: "KRN-009", keys: []string{
		"net.ipv4.conf.all.rp_filter", "net.ipv4.conf.default.rp_filter",
	}, want: "1", severity: Medium, title: "Strict reverse path filtering is enabled"},
	{id: "KRN-010", keys: []string{"fs.protected_symlinks"}, want: "1", severity: Medium, title: "Symlink protection is enabled"},
	{id: "KRN-011", keys: []string{"fs.protected_hardlinks"}, want: "1", severity: Medium, title: "Hardlink protection is enabled"},
	{id: "KRN-012", keys: []string{"fs.suid_dumpable"}, want: "0", severity: Medium, title: "setuid programs cannot dump core"},
	{id: "KRN-013", keys: []string{
		"net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route",
		"net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route",
	}, want: "0", severity: Medium, title: "Source-routed packets are rejected (IPv4 and IPv6)"},
	{id: "KRN-014", keys: []string{
		"net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra",
	}, want: "0", severity: Low, title: "IPv6 router advertisements are ignored",
		note: " (skip this check on hosts that get their IPv6 address from router advertisements/SLAAC)"},
}

// ipv6Disabled reports whether the kernel has no IPv6 stack at all, in which
// case IPv6 settings cannot be weak.
func ipv6Disabled(h *platform.Host) bool {
	return !h.Exists("/proc/sys/net/ipv6")
}

func (r sysctlRule) satisfied(got string) bool {
	if !r.min {
		return got == r.want
	}
	g, err := strconv.Atoi(got)
	w, _ := strconv.Atoi(r.want)
	return err == nil && g >= w
}

func (r sysctlRule) remediation() string {
	lines := make([]string, len(r.keys))
	for i, k := range r.keys {
		lines[i] = fmt.Sprintf("`%s = %s`", k, r.want)
	}
	return fmt.Sprintf("Add %s to %s and run `sysctl --system`%s", strings.Join(lines, ", "), sysctlDropIn, r.note)
}

func (r sysctlRule) check() Check {
	want := r.want
	if r.min {
		want = "≥ " + want
	}
	return Check{
		ID: r.id, Title: r.title, Category: "Kernel", Control: "A.8.9", Severity: r.severity,
		Remediation: r.remediation(),
		run: func(_ context.Context, h *platform.Host) Result {
			var bad []string
			checked, ipv6Off := 0, false
			for _, key := range r.keys {
				got, err := readSysctl(h, key)
				if isNotExist(err) {
					if strings.HasPrefix(key, "net.ipv6.") && ipv6Disabled(h) {
						ipv6Off = true
						continue
					}
					bad = append(bad, key+" is not available on this kernel")
					continue
				}
				if err != nil {
					return errored(err)
				}
				checked++
				if !r.satisfied(got) {
					bad = append(bad, fmt.Sprintf("%s = %s", key, got))
				}
			}

			if len(bad) > 0 {
				res := fail("%s (want %s)", joinLimited(bad, 4), want)
				if r.id == "KRN-006" && containerHost(h) {
					res.Detail += "; container runtime detected, forwarding may be required: skip with --skip " + r.id
				}
				return res
			}
			switch {
			case checked == 0 && ipv6Off:
				return pass("IPv6 is disabled in the kernel")
			case len(r.keys) == 1:
				return pass("%s = %s", r.keys[0], r.want)
			case ipv6Off:
				return pass("all IPv4 settings = %s (IPv6 is disabled in the kernel)", r.want)
			}
			return pass("all %d settings = %s", checked, r.want)
		},
	}
}

func init() {
	for _, r := range sysctlRules {
		register(r.check())
	}
}
