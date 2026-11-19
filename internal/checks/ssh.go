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

// sshdNoHostKeys is what sshd prints when it has no host keys yet.
const sshdNoHostKeys = "no hostkeys available"

// sshValidate is appended to remediations that change algorithms: a typo or
// an algorithm the installed OpenSSH lacks stops sshd from starting, which
// locks out remote admins on restart.
const sshValidate = "Run `sshd -t` before restarting sshd; keep an existing session open."

// sshdSettings is the effective sshd configuration with lowercased keys.
type sshdSettings struct {
	values map[string]string
	// fromSSHD is true when values came from `sshd -T` (authoritative), false
	// when they were parsed from the config files plus known defaults.
	fromSSHD bool
	// matches are the conditional "Match" sections. `sshd -T` without -C
	// prints only the global view, so these are always read from the files.
	matches []*sshdMatchBlock
	// matchErr is set when the files could not be read to look for Match
	// blocks; a global pass then cannot be trusted.
	matchErr error
	// noHostKeys means sshd has never generated its host keys (it does so on
	// first start), so `sshd -T` refused to run and values come from the files.
	noHostKeys bool
}

// sshdMatchBlock is one "Match <criteria>" section and the settings it
// overrides for connections that satisfy the criteria.
type sshdMatchBlock struct {
	criteria string
	file     string
	values   map[string]string
}

// sshdConfig is the raw parse of the config files.
type sshdConfig struct {
	global  map[string]string
	matches []*sshdMatchBlock
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
	"clientaliveinterval":          "0",
	"clientalivecountmax":          "3",
	"x11forwarding":                "no",
	"allowtcpforwarding":           "yes",
	"loglevel":                     "info",
	"logingracetime":               "120",
}

// parseSSHTime parses sshd's time format: plain seconds ("60") or units
// s/m/h/d/w, possibly combined ("1m30s"). `sshd -T` prints plain seconds;
// config files may use units.
func parseSSHTime(v string) (int, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0, fmt.Errorf("empty time value")
	}
	// Digits and unit letters only: no signs, so Atoi's "-1"/"+1" never apply.
	const maxSeconds = 1 << 40 // far beyond any sane value; prevents overflow
	units := map[byte]int{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	total, num := 0, ""
	add := func(unit int) error {
		n, err := strconv.Atoi(num)
		if err != nil || n > maxSeconds {
			return fmt.Errorf("invalid time value %q", v)
		}
		total += n * unit
		if total > maxSeconds {
			return fmt.Errorf("time value %q too large", v)
		}
		num = ""
		return nil
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			num += string(c)
		case units[c] != 0 && num != "":
			if err := add(units[c]); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("invalid time value %q", v)
		}
	}
	if num != "" {
		if err := add(1); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// sshTimeAtMost accepts a time value between 1 and max seconds.
func sshTimeAtMost(max int) func(string) bool {
	return func(v string) bool {
		n, err := parseSSHTime(v)
		return err == nil && n > 0 && n <= max
	}
}

func intAtMost(max int) func(string) bool {
	return func(v string) bool {
		n, err := strconv.Atoi(v)
		return err == nil && n <= max
	}
}

func loadSSHD(ctx context.Context, h *platform.Host) (*sshdSettings, error) {
	v, err := h.Memo("sshd", func() (any, error) {
		// `sshd -T` prints the fully resolved config, including Includes,
		// distro crypto policies and compiled-in defaults.
		res, runErr := h.Run.Run(ctx, "sshd", "-T")
		if runErr == nil && res.ExitCode == 0 && len(res.Stdout) > 0 {
			s := &sshdSettings{values: parseSSHDTest(res.Stdout), fromSSHD: true}
			cfg, err := parseSSHDConfig(h)
			switch {
			case isNotExist(err):
				// sshd runs on compiled-in defaults: no Match blocks.
			case err != nil:
				s.matchErr = err
			default:
				s.matches = cfg.matches
			}
			return s, nil
		}
		if !h.Exists(sshdConfigPath) {
			if errors.Is(runErr, platform.ErrCommandNotFound) {
				return nil, errSSHNotInstalled
			}
		}
		// As root, `sshd -T` only fails when sshd itself would refuse to start
		// (bad option, unsupported algorithm, missing host keys). Parsing the
		// files instead would grade a config that cannot run as hardened.
		// Without root it fails on unreadable host keys, so fall back.
		//
		// The one exception is missing host keys: distros create them when the
		// service first starts (sshd-keygen), so a never-started sshd has none.
		// sshd validates the whole config before it loads host keys, so this
		// message also means the config itself was accepted.
		noHostKeys := false
		if runErr == nil && res.ExitCode != 0 && h.IsRoot {
			if !strings.Contains(string(res.Stderr), sshdNoHostKeys) {
				return nil, fmt.Errorf("sshd rejects its configuration and would not start: %s", firstLine(res.Stderr))
			}
			noHostKeys = true
		}
		cfg, err := parseSSHDConfig(h)
		if err != nil {
			return nil, fmt.Errorf("cannot read sshd configuration: %w", err)
		}
		for k, def := range sshdDefaults {
			if _, ok := cfg.global[k]; !ok {
				cfg.global[k] = def
			}
		}
		return &sshdSettings{values: cfg.global, matches: cfg.matches, noHostKeys: noHostKeys}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*sshdSettings), nil
}

// firstLine returns the first non-empty line of command output.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return truncate(line, 160)
		}
	}
	return "no error output"
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

// parseSSHDConfig reads sshd_config and everything it includes.
func parseSSHDConfig(h *platform.Host) (*sshdConfig, error) {
	cfg := &sshdConfig{global: map[string]string{}}
	if err := parseSSHDConfigFile(h, sshdConfigPath, cfg, nil, 0); err != nil {
		return nil, err
	}
	// Older OpenSSH spells the keyboard-interactive switch differently.
	for _, values := range append([]map[string]string{cfg.global}, matchValues(cfg.matches)...) {
		if v, ok := values["challengeresponseauthentication"]; ok {
			if _, set := values["kbdinteractiveauthentication"]; !set {
				values["kbdinteractiveauthentication"] = v
			}
		}
	}
	return cfg, nil
}

func matchValues(blocks []*sshdMatchBlock) []map[string]string {
	out := make([]map[string]string, len(blocks))
	for i, b := range blocks {
		out[i] = b.values
	}
	return out
}

// parseSSHDConfigFile applies sshd's "first value wins" rule across a config
// file and its Includes. block is the Match section the file is included
// from (nil at the top level): an Include inside a Match block belongs to
// that block. A Match section ends at the next Match line or at the end of
// the file it appears in.
func parseSSHDConfigFile(h *platform.Host, path string, cfg *sshdConfig, block *sshdMatchBlock, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("%s: Include nesting deeper than %d", path, maxIncludeDepth)
	}
	data, err := h.ReadFile(path)
	if err != nil {
		return err
	}
	cur := block
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		key, val := splitSSHDLine(line)
		key = strings.ToLower(key)
		switch key {
		case "match":
			cur = &sshdMatchBlock{criteria: val, file: path, values: map[string]string{}}
			cfg.matches = append(cfg.matches, cur)
			continue
		case "include":
			for _, pattern := range strings.Fields(val) {
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join("/etc/ssh", pattern)
				}
				matches, err := h.Glob(pattern)
				if err != nil {
					return err
				}
				for _, m := range matches {
					if err := parseSSHDConfigFile(h, m, cfg, cur, depth+1); err != nil && !isNotExist(err) {
						return err
					}
				}
			}
			continue
		}
		target := cfg.global
		if cur != nil {
			target = cur.values
		}
		if _, seen := target[key]; !seen {
			target[key] = strings.ToLower(strings.Trim(val, `"`))
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
		if s.noHostKeys && (r.Status == Pass || r.Status == Fail) {
			r.Detail += " (read from the config files: sshd has no host keys yet, they are created when it first starts)"
		}
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
	return expectSetting(key, want, func(v string) bool { return v == want })
}

// expectSetting checks the global value of key and every Match block that
// overrides it. want is only used in messages.
func expectSetting(key, want string, ok func(string) bool) func(*sshdSettings) Result {
	return func(s *sshdSettings) Result {
		got, set := s.get(key)
		var r Result
		switch {
		case !set:
			r = fail("%s is not set", key)
		case ok(got):
			r = pass("%s %s", key, got)
		default:
			r = fail("%s %s (want %s)", key, got, want)
		}
		return s.checkMatches(r, key, ok)
	}
}

// checkMatches downgrades a global result when a Match block weakens key for
// some connections (e.g. `Match User backup` + `PasswordAuthentication yes`).
// Any weakening block is flagged, whether or not an earlier block would
// shadow it for some connections: the scanner never assumes a block is dead.
func (s *sshdSettings) checkMatches(r Result, key string, ok func(string) bool) Result {
	if s.matchErr != nil {
		if r.Status == Pass {
			return errored(fmt.Errorf("%s globally, but Match blocks could not be checked: %w", r.Detail, s.matchErr))
		}
		return r
	}
	var bad []string
	for _, m := range s.matches {
		if v, set := m.values[key]; set && !ok(v) {
			bad = append(bad, fmt.Sprintf("`Match %s` in %s sets %s %s", m.criteria, filepath.Base(m.file), key, v))
		}
	}
	if len(bad) == 0 {
		return r
	}
	if r.Status == Pass {
		return fail("%s globally, but %s", r.Detail, joinLimited(bad, 3))
	}
	r.Detail += "; also " + joinLimited(bad, 3)
	return r
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
		}, expectSetting("maxauthtries", "≤ 3", func(v string) bool {
			n, err := strconv.Atoi(v)
			return err == nil && n <= 3
		})),

		sshCheck(Check{
			ID: "SSH-006", Title: "SSH public key authentication is enabled", Control: "A.8.2", Severity: Low,
			Remediation: "Set `PubkeyAuthentication yes` in " + sshDropIn,
		}, expectValue("pubkeyauthentication", "yes")),

		sshCheck(Check{
			ID: "SSH-010", Title: "Idle SSH sessions time out", Control: "A.8.2", Severity: Medium,
			Remediation: "Set `ClientAliveInterval 300` and `ClientAliveCountMax 3` in " + sshDropIn,
		}, func(s *sshdSettings) Result {
			interval := sshTimeAtMost(300)
			count := intAtMost(3)
			iv, _ := s.get("clientaliveinterval")
			cv, _ := s.get("clientalivecountmax")
			var r Result
			switch {
			case !interval(iv):
				r = fail("clientaliveinterval %s (want 1-300 seconds; 0 never disconnects idle sessions)", iv)
			case !count(cv):
				r = fail("clientalivecountmax %s (want ≤ 3)", cv)
			default:
				r = pass("clientaliveinterval %s, clientalivecountmax %s", iv, cv)
			}
			r = s.checkMatches(r, "clientaliveinterval", interval)
			return s.checkMatches(r, "clientalivecountmax", count)
		}),

		sshCheck(Check{
			ID: "SSH-011", Title: "SSH X11 forwarding is disabled", Control: "A.8.2", Severity: Low,
			Remediation: "Set `X11Forwarding no` in " + sshDropIn,
		}, expectValue("x11forwarding", "no")),

		sshCheck(Check{
			ID: "SSH-012", Title: "SSH TCP forwarding is disabled", Control: "A.8.2", Severity: Low,
			Remediation: "Set `AllowTcpForwarding no` in " + sshDropIn + " (allow it only in a `Match` block for users who need tunnels)",
		}, expectValue("allowtcpforwarding", "no")),

		sshCheck(Check{
			ID: "SSH-013", Title: "SSH logs at VERBOSE level", Control: "A.8.15", Severity: Low,
			Remediation: "Set `LogLevel VERBOSE` in " + sshDropIn + " so each login records the key fingerprint used",
		}, expectSetting("loglevel", "VERBOSE", func(v string) bool { return strings.EqualFold(v, "verbose") })),

		sshCheck(Check{
			ID: "SSH-014", Title: "SSH login grace time is 60 seconds or less", Control: "A.8.2", Severity: Low,
			Remediation: "Set `LoginGraceTime 60` in " + sshDropIn,
		}, func(s *sshdSettings) Result {
			// LoginGraceTime is not allowed inside Match blocks.
			v, _ := s.get("logingracetime")
			if sshTimeAtMost(60)(v) {
				return pass("logingracetime %s", v)
			}
			return fail("logingracetime %s (want 1-60 seconds; 0 means unlimited)", v)
		}),

		sshCheck(Check{
			ID: "SSH-007", Title: "SSH key exchange uses modern algorithms only", Control: "A.8.24", Severity: High,
			Remediation: "Set `KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org` in " + sshDropIn +
				" (on OpenSSH 9.9+ you may prepend `mlkem768x25519-sha256`; older versions refuse to start with it). " + sshValidate,
		}, expectSubset("kexalgorithms",
			"mlkem768x25519-sha256",
			"sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com",
			"curve25519-sha256", "curve25519-sha256@libssh.org",
			"kex-strict-s-v00@openssh.com",
		)),

		sshCheck(Check{
			ID: "SSH-008", Title: "SSH ciphers are AEAD only", Control: "A.8.24", Severity: High,
			Remediation: "Set `Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com` in " + sshDropIn + ". " + sshValidate,
		}, expectSubset("ciphers",
			"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
		)),

		sshCheck(Check{
			ID: "SSH-009", Title: "SSH MACs are encrypt-then-MAC SHA-2 only", Control: "A.8.24", Severity: Medium,
			Remediation: "Set `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com` in " + sshDropIn + ". " + sshValidate,
		}, expectSubset("macs",
			"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com",
		)),
	)
}
