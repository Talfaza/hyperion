package checks

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// sshDropIn sorts first on purpose. sshd uses the first value it sees and
// reads sshd_config.d/*.conf in lexical order, so a "99-" file would lose to
// distro files such as Fedora's 50-redhat.conf (which pulls in the system
// crypto policy) or Ubuntu's 50-cloud-init.conf (PasswordAuthentication yes).
const sshDropIn = "/etc/ssh/sshd_config.d/00-hyperion-hardening.conf"

var errSSHNotInstalled = errors.New("OpenSSH server is not installed")

// sshdSettings is the effective sshd configuration with lowercased keys.
type sshdSettings struct {
	values map[string]string
	// fromSSHD is true when values came from `sshd -T` (authoritative), false
	// when they were parsed from the config files plus known defaults.
	fromSSHD bool
}

func (s *sshdSettings) get(key string) (string, bool) {
	v, ok := s.values[key]
	return v, ok
}

// Defaults that apply when a keyword is absent from sshd_config. Only used in
// the file-parsing fallback; `sshd -T` already reports effective values.
var sshdDefaults = map[string]string{
	"permitrootlogin":              "prohibit-password",
	"passwordauthentication":       "yes",
	"kbdinteractiveauthentication": "yes",
	"permitemptypasswords":         "no",
	"pubkeyauthentication":         "yes",
	"maxauthtries":                 "6",
}

func loadSSHD(ctx context.Context, h *platform.Host) (*sshdSettings, error) {
	v, err := h.Memo("sshd", func() (any, error) {
		// `sshd -T` prints the fully resolved config, including Includes,
		// distro crypto policies and compiled-in defaults.
		res, runErr := h.Run.Run(ctx, "sshd", "-T")
		if runErr == nil && res.ExitCode == 0 && len(res.Stdout) > 0 {
			return &sshdSettings{values: parseSSHDTest(res.Stdout), fromSSHD: true}, nil
		}
		if !h.Exists(sshdConfigPath) {
			if errors.Is(runErr, platform.ErrCommandNotFound) {
				return nil, errSSHNotInstalled
			}
		}
		values := map[string]string{}
		if err := parseSSHDConfigFile(h, sshdConfigPath, values, 0); err != nil {
			return nil, fmt.Errorf("cannot read sshd configuration: %w", err)
		}
		// Older OpenSSH spells the keyboard-interactive switch differently.
		if v, ok := values["challengeresponseauthentication"]; ok {
			if _, set := values["kbdinteractiveauthentication"]; !set {
				values["kbdinteractiveauthentication"] = v
			}
		}
		for k, def := range sshdDefaults {
			if _, ok := values[k]; !ok {
				values[k] = def
			}
		}
		return &sshdSettings{values: values}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*sshdSettings), nil
}

func parseSSHDTest(out []byte) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		k = strings.ToLower(k)
		if _, seen := values[k]; !seen {
			values[k] = strings.TrimSpace(v)
		}
	}
	return values
}

const maxIncludeDepth = 16

// parseSSHDConfigFile applies sshd's "first value wins" rule across a config
// file and its Includes. Lines inside Match blocks are conditional and are
// ignored for the global view.
func parseSSHDConfigFile(h *platform.Host, path string, values map[string]string, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("%s: Include nesting deeper than %d", path, maxIncludeDepth)
	}
	data, err := h.ReadFile(path)
	if err != nil {
		return err
	}
	inMatch := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		key, val := splitSSHDLine(line)
		key = strings.ToLower(key)
		switch {
		case key == "match":
			inMatch = true
			continue
		case inMatch:
			continue
		case key == "include":
			for _, pattern := range strings.Fields(val) {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join("/etc/ssh", pattern)
				}
				matches, err := h.Glob(pattern)
				if err != nil {
					return err
				}
				for _, m := range matches {
					if err := parseSSHDConfigFile(h, m, values, depth+1); err != nil && !isNotExist(err) {
						return err
					}
				}
			}
			continue
		}
		if _, seen := values[key]; !seen {
			values[key] = strings.ToLower(strings.Trim(val, `"`))
		}
	}
	return nil
}

// splitSSHDLine splits "Keyword value" or "Keyword=value".
func splitSSHDLine(line string) (string, string) {
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return line, ""
	}
	key := line[:i]
	rest := strings.TrimLeft(line[i:], " \t")
	rest = strings.TrimPrefix(rest, "=")
	return key, strings.TrimSpace(rest)
}

func sshCheck(c Check, eval func(s *sshdSettings) Result) Check {
	c.Category = "SSH"
	c.NeedsRoot = true
	c.run = func(ctx context.Context, h *platform.Host) Result {
		s, err := loadSSHD(ctx, h)
		if errors.Is(err, errSSHNotInstalled) {
			return skip("%v", err)
		}
		if err != nil {
			return errored(err)
		}
		r := eval(s)
		if r.Status == Fail && !sshdRunning(ctx, h) {
			r.Detail += "; sshd is not running, so this is not exposed until it is started"
		}
		return r
	}
	return c
}

// sshdRunning reports whether the SSH daemon is active. When systemd is not
// available the answer is unknown and it reports true, so no finding is ever
// softened on a guess.
func sshdRunning(ctx context.Context, h *platform.Host) bool {
	v, _ := h.Memo("sshd-running", func() (any, error) {
		known := false
		for _, unit := range []string{"sshd.service", "ssh.service"} {
			state, err := unitState(ctx, h, "is-active", unit)
			if err != nil {
				continue
			}
			known = true
			if state == "active" {
				return true, nil
			}
		}
		return !known, nil
	})
	return v.(bool)
}

func expectValue(key, want string) func(*sshdSettings) Result {
	return func(s *sshdSettings) Result {
		got, ok := s.get(key)
		if !ok {
			return fail("%s is not set", key)
		}
		if got == want {
			return pass("%s %s", key, got)
		}
		return fail("%s %s (want %s)", key, got, want)
	}
}

// expectSubset passes when every algorithm configured for key is on the allowlist.
func expectSubset(key string, allowed ...string) func(*sshdSettings) Result {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	return func(s *sshdSettings) Result {
		got, set := s.get(key)
		if !set {
			return fail("%s is not explicitly restricted; OpenSSH defaults include legacy algorithms", key)
		}
		if got == "" {
			return fail("%s is empty", key)
		}
		if strings.ContainsAny(got[:1], "+-^") {
			return fail("%s modifies the default list (%s); set an explicit list", key, truncate(got, 60))
		}
		var weak []string
		for _, alg := range strings.Split(got, ",") {
			alg = strings.TrimSpace(alg)
			if alg != "" && !ok[alg] {
				weak = append(weak, alg)
			}
		}
		if len(weak) > 0 {
			return fail("weak or non-approved %s: %s", key, joinLimited(weak, 4))
		}
		return pass("%s restricted to approved algorithms", key)
	}
}

func init() {
	register(
		sshCheck(Check{
			ID: "SSH-001", Title: "Root login over SSH is disabled", Control: "A.8.2", Severity: Critical,
			Remediation: "Set `PermitRootLogin no` in " + sshDropIn,
		}, expectValue("permitrootlogin", "no")),

		sshCheck(Check{
			ID: "SSH-002", Title: "SSH password authentication is disabled", Control: "A.8.2", Severity: High,
			Remediation: "Set `PasswordAuthentication no` in " + sshDropIn,
		}, expectValue("passwordauthentication", "no")),

		sshCheck(Check{
			ID: "SSH-003", Title: "SSH keyboard-interactive authentication is disabled", Control: "A.8.2", Severity: Medium,
			Remediation: "Set `KbdInteractiveAuthentication no` in " + sshDropIn,
		}, expectValue("kbdinteractiveauthentication", "no")),

		sshCheck(Check{
			ID: "SSH-004", Title: "SSH empty passwords are rejected", Control: "A.8.2", Severity: Critical,
			Remediation: "Set `PermitEmptyPasswords no` in " + sshDropIn,
		}, expectValue("permitemptypasswords", "no")),

		sshCheck(Check{
			ID: "SSH-005", Title: "SSH MaxAuthTries is 3 or less", Control: "A.8.2", Severity: Medium,
			Remediation: "Set `MaxAuthTries 3` in " + sshDropIn,
		}, func(s *sshdSettings) Result {
			raw, _ := s.get("maxauthtries")
			n, err := strconv.Atoi(raw)
			if err != nil {
				return fail("maxauthtries has invalid value %q", raw)
			}
			if n <= 3 {
				return pass("maxauthtries %d", n)
			}
			return fail("maxauthtries %d (want ≤ 3)", n)
		}),

		sshCheck(Check{
			ID: "SSH-006", Title: "SSH public key authentication is enabled", Control: "A.8.2", Severity: Low,
			Remediation: "Set `PubkeyAuthentication yes` in " + sshDropIn,
		}, expectValue("pubkeyauthentication", "yes")),

		sshCheck(Check{
			ID: "SSH-007", Title: "SSH key exchange uses modern algorithms only", Control: "A.8.24", Severity: High,
			Remediation: "Set `KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org` in " + sshDropIn,
		}, expectSubset("kexalgorithms",
			"mlkem768x25519-sha256",
			"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"kex-strict-s-v00@openssh.com",
		)),

		sshCheck(Check{
			ID: "SSH-008", Title: "SSH ciphers are AEAD only", Control: "A.8.24", Severity: High,
			Remediation: "Set `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com` in " + sshDropIn,
		}, expectSubset("ciphers",
			"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
		)),

		sshCheck(Check{
			ID: "SSH-009", Title: "SSH MACs are encrypt-then-MAC SHA-2 only", Control: "A.8.24", Severity: Medium,
			Remediation: "Set `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com` in " + sshDropIn,
		}, expectSubset("macs",
			"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com",
		)),
	)
}
