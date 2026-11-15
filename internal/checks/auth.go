package checks

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

// ---- sudoers ---------------------------------------------------------------

type sudoLine struct {
	file string
	text string
}

const sudoersPath = "/etc/sudoers"

// loadSudoers returns the logical lines of /etc/sudoers and everything it
// includes, in evaluation order.
func loadSudoers(h *platform.Host) ([]sudoLine, error) {
	v, err := h.Memo("sudoers", func() (any, error) {
		var lines []sudoLine
		err := readSudoersFile(h, sudoersPath, &lines, 0)
		return lines, err
	})
	if err != nil {
		return nil, err
	}
	return v.([]sudoLine), nil
}

func readSudoersFile(h *platform.Host, file string, out *[]sudoLine, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("%s: include nesting deeper than %d", file, maxIncludeDepth)
	}
	data, err := h.ReadFile(file)
	if err != nil {
		return err
	}
	for _, line := range sudoLogicalLines(data) {
		directive, arg := sudoInclude(line)
		switch directive {
		case "includedir":
			entries, err := h.Glob(path.Join(arg, "*"))
			if err != nil {
				return err
			}
			for _, e := range entries {
				// sudo skips files ending in '~' or containing '.'.
				base := path.Base(e)
				if strings.HasSuffix(base, "~") || strings.Contains(base, ".") {
					continue
				}
				if err := readSudoersFile(h, e, out, depth+1); err != nil && !isNotExist(err) {
					return err
				}
			}
		case "include":
			if !path.IsAbs(arg) {
				arg = path.Join(path.Dir(file), arg)
			}
			if err := readSudoersFile(h, arg, out, depth+1); err != nil && !isNotExist(err) {
				return err
			}
		default:
			if line != "" && line[0] != '#' {
				*out = append(*out, sudoLine{file: file, text: line})
			}
		}
	}
	return nil
}

// sudoLogicalLines joins backslash-continued lines and trims whitespace.
func sudoLogicalLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// sudoInclude recognises @include/#include and @includedir/#includedir.
func sudoInclude(line string) (directive, arg string) {
	if len(line) < 2 || (line[0] != '@' && line[0] != '#') {
		return "", ""
	}
	fields := strings.Fields(line[1:])
	if len(fields) != 2 {
		return "", ""
	}
	switch fields[0] {
	case "include", "includedir":
		return fields[0], strings.Trim(fields[1], `"`)
	}
	return "", ""
}

// sudoDefaultsOptions returns the comma-separated options of a Defaults line,
// or nil when the line is not a Defaults line.
func sudoDefaultsOptions(line string) []string {
	if !strings.HasPrefix(line, "Defaults") {
		return nil
	}
	rest := line[len("Defaults"):]
	// Scoped forms: Defaults:user, Defaults@host, Defaults>runas, Defaults!cmd
	if rest != "" && strings.ContainsRune(":@>!", rune(rest[0])) {
		_, after, ok := strings.Cut(rest, " ")
		if !ok {
			return nil
		}
		rest = after
	}
	var opts []string
	for _, o := range strings.Split(rest, ",") {
		if o = strings.TrimSpace(o); o != "" {
			opts = append(opts, strings.ReplaceAll(o, " ", ""))
		}
	}
	return opts
}

func evalSudoTimeout(lines []sudoLine) Result {
	worst := 5.0 // sudo's compiled-in default
	where := "default"
	for _, l := range lines {
		for _, o := range sudoDefaultsOptions(l.text) {
			v, ok := strings.CutPrefix(o, "timestamp_timeout=")
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(strings.Trim(v, `"`), 64)
			if err != nil {
				return fail("%s: invalid timestamp_timeout %q", l.file, v)
			}
			if n < 0 {
				return fail("%s: timestamp_timeout=%s means sudo never asks again", l.file, v)
			}
			if n > worst {
				worst, where = n, l.file
			}
		}
	}
	if worst <= 5 {
		return pass("timestamp_timeout %g min (%s)", worst, where)
	}
	return fail("timestamp_timeout %g min in %s (want ≤ 5)", worst, where)
}

func evalSudoReauth(lines []sudoLine) Result {
	var offenders []string
	for _, l := range lines {
		if strings.Contains(l.text, "NOPASSWD") {
			offenders = append(offenders, path.Base(l.file)+": "+truncate(l.text, 50))
			continue
		}
		for _, o := range sudoDefaultsOptions(l.text) {
			if o == "!authenticate" {
				offenders = append(offenders, path.Base(l.file)+": "+truncate(l.text, 50))
			}
		}
	}
	if len(offenders) > 0 {
		return fail("sudo without password: %s", joinLimited(offenders, 3))
	}
	return pass("all sudo rules require authentication")
}

func sudoCheck(c Check, eval func([]sudoLine) Result) Check {
	c.Category = "Access"
	c.NeedsRoot = true
	c.run = func(_ context.Context, h *platform.Host) Result {
		lines, err := loadSudoers(h)
		if isNotExist(err) {
			return skip("sudo is not installed")
		}
		if err != nil {
			return errored(err)
		}
		return eval(lines)
	}
	return c
}

// ---- password quality --------------------------------------------------------

var pamPasswordStacks = []string{
	"/etc/pam.d/common-password", // Debian/Ubuntu
	"/etc/pam.d/system-auth",     // RHEL family
	"/etc/pam.d/password-auth",
}

func checkPwquality(_ context.Context, h *platform.Host) Result {
	files := []string{"/etc/security/pwquality.conf"}
	dropins, err := h.Glob("/etc/security/pwquality.conf.d/*.conf")
	if err != nil {
		return errored(err)
	}
	files = append(files, dropins...)
	cfg, found, err := mergeConfigs(h.ReadFile, files)
	if err != nil {
		return errored(err)
	}
	if len(found) == 0 {
		return fail("pam_pwquality is not configured (no pwquality.conf)")
	}

	var problems []string
	if n, err := strconv.Atoi(cfg["minlen"]); err != nil || n < 14 {
		problems = append(problems, fmt.Sprintf("minlen=%s (want ≥ 14)", orUnset(cfg["minlen"])))
	}
	for _, k := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		if n, err := strconv.Atoi(cfg[k]); err != nil || n > -1 {
			problems = append(problems, fmt.Sprintf("%s=%s (want ≤ -1)", k, orUnset(cfg[k])))
		}
	}

	enforced := false
	for _, p := range pamPasswordStacks {
		if data, err := h.ReadFile(p); err == nil && strings.Contains(string(data), "pam_pwquality.so") {
			enforced = true
			break
		}
	}
	if !enforced {
		problems = append(problems, "pam_pwquality.so is not in the PAM password stack")
	}

	if len(problems) > 0 {
		return fail("%s", strings.Join(problems, "; "))
	}
	return pass("minlen=%s with all character classes required", cfg["minlen"])
}

func orUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}

// ---- accounts ----------------------------------------------------------------

func checkDefaultInactive(_ context.Context, h *platform.Host) Result {
	data, err := h.ReadFile("/etc/default/useradd")
	if isNotExist(err) {
		return fail("/etc/default/useradd missing; new accounts never lock (INACTIVE=-1)")
	}
	if err != nil {
		return errored(err)
	}
	raw := platform.ParseEnvFile(data)["INACTIVE"]
	if raw == "" {
		return fail("INACTIVE unset; new accounts never lock")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 30 {
		return fail("INACTIVE=%s (want 0-30)", raw)
	}
	return pass("INACTIVE=%d", n)
}

type shadowEntry struct {
	name, hash, inactive string
}

func loadShadow(h *platform.Host) ([]shadowEntry, error) {
	data, err := h.ReadFile("/etc/shadow")
	if err != nil {
		return nil, err
	}
	var out []shadowEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		out = append(out, shadowEntry{name: f[0], hash: f[1], inactive: f[6]})
	}
	return out, nil
}

// hasUsablePassword: a hash that is not locked (!), disabled (*) or empty.
func (e shadowEntry) hasUsablePassword() bool {
	return e.hash != "" && e.hash[0] != '!' && e.hash[0] != '*'
}

func checkAccountInactive(_ context.Context, h *platform.Host) Result {
	entries, err := loadShadow(h)
	if err != nil {
		return errored(err)
	}
	var bad []string
	for _, e := range entries {
		if !e.hasUsablePassword() {
			continue
		}
		n, err := strconv.Atoi(e.inactive)
		if err != nil || n < 0 || n > 30 {
			bad = append(bad, e.name)
		}
	}
	if len(bad) > 0 {
		return fail("accounts without a ≤30 day inactivity lock: %s", joinLimited(bad, 5))
	}
	return pass("all password accounts lock after ≤ 30 days of inactivity")
}

func checkEmptyPasswords(_ context.Context, h *platform.Host) Result {
	entries, err := loadShadow(h)
	if err != nil {
		return errored(err)
	}
	var bad []string
	for _, e := range entries {
		if e.hash == "" {
			bad = append(bad, e.name)
		}
	}
	if len(bad) > 0 {
		return fail("accounts with an empty password: %s", joinLimited(bad, 5))
	}
	return pass("no accounts with empty passwords")
}

func checkUID0(_ context.Context, h *platform.Host) Result {
	data, err := h.ReadFile("/etc/passwd")
	if err != nil {
		return errored(err)
	}
	var extra []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
			extra = append(extra, f[0])
		}
	}
	if len(extra) > 0 {
		return fail("non-root accounts with UID 0: %s", joinLimited(extra, 5))
	}
	return pass("only root has UID 0")
}

func init() {
	register(
		sudoCheck(Check{
			ID: "AUTH-001", Title: "sudo re-authenticates within 5 minutes", Control: "A.8.2", Severity: Medium,
			Remediation: "Add `Defaults timestamp_timeout=5` to /etc/sudoers.d/hyperion (edit with visudo)",
		}, evalSudoTimeout),
		sudoCheck(Check{
			ID: "AUTH-002", Title: "sudo always requires a password", Control: "A.8.2", Severity: Medium,
			Remediation: "Remove NOPASSWD tags and `!authenticate` from sudoers rules (edit with visudo)",
		}, evalSudoReauth),
		Check{
			ID: "AUTH-003", Title: "Password complexity is enforced", Category: "Access", Control: "A.8.2", Severity: Medium,
			Remediation: "Install pam_pwquality and set minlen = 14, dcredit/ucredit/lcredit/ocredit = -1 in /etc/security/pwquality.conf",
			run:         checkPwquality,
		},
		Check{
			ID: "AUTH-004", Title: "New accounts lock after 30 days inactive", Category: "Access", Control: "A.8.2", Severity: Low,
			Remediation: "Run `useradd -D -f 30`",
			run:         checkDefaultInactive,
		},
		Check{
			ID: "AUTH-005", Title: "Existing accounts lock after 30 days inactive", Category: "Access", Control: "A.8.2", Severity: Low,
			Remediation: "Run `chage --inactive 30 <user>` for each listed account",
			NeedsRoot:   true,
			run:         checkAccountInactive,
		},
		Check{
			ID: "AUTH-006", Title: "No accounts have empty passwords", Category: "Access", Control: "A.8.2", Severity: Critical,
			Remediation: "Lock the account with `passwd -l <user>` or set a password",
			NeedsRoot:   true,
			run:         checkEmptyPasswords,
		},
		Check{
			ID: "AUTH-007", Title: "Only root has UID 0", Category: "Access", Control: "A.8.2", Severity: Critical,
			Remediation: "Remove or renumber the extra UID 0 accounts; investigate how they were created",
			run:         checkUID0,
		},
	)
}
