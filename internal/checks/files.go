package checks

import (
	"context"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"syscall"

	"github.com/Talfaza/hyperion/internal/platform"
)

// evalFileMode checks owner and that no permission bit outside maxPerm is set.
func evalFileMode(path string, info fs.FileInfo, maxPerm fs.FileMode) Result {
	if !info.Mode().IsRegular() {
		return fail("%s is not a regular file (%s)", path, info.Mode().Type())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errored(fmt.Errorf("%s: cannot read ownership", path))
	}
	perm := info.Mode().Perm()
	var problems []string
	if st.Uid != 0 {
		problems = append(problems, fmt.Sprintf("owned by uid %d (want root)", st.Uid))
	}
	if extra := perm &^ maxPerm; extra != 0 {
		problems = append(problems, fmt.Sprintf("mode %04o is more permissive than %04o", perm, maxPerm))
	}
	if info.Mode()&(fs.ModeSetuid|fs.ModeSetgid) != 0 {
		problems = append(problems, "setuid/setgid bit set")
	}
	if len(problems) > 0 {
		return fail("%s %s", path, strings.Join(problems, ", "))
	}
	return pass("%s mode %04o, owner root", path, perm)
}

func fileModeCheck(c Check, path string, maxPerm fs.FileMode, skipIfMissing bool) Check {
	c.Category = "Files"
	c.run = func(_ context.Context, h *platform.Host) Result {
		info, err := h.Lstat(path)
		if isNotExist(err) && skipIfMissing {
			return skip("%s does not exist", path)
		}
		if err != nil {
			return errored(err)
		}
		return evalFileMode(path, info, maxPerm)
	}
	return c
}

// ---- umask ------------------------------------------------------------------

var umaskLocations = []string{"/etc/profile", "/etc/bashrc", "/etc/bash.bashrc"}

func umaskStrict(v string) (bool, error) {
	n, err := strconv.ParseUint(v, 8, 32)
	if err != nil {
		return false, fmt.Errorf("invalid umask %q", v)
	}
	return n&0o027 == 0o027, nil
}

func checkUmask(_ context.Context, h *platform.Host) Result {
	var problems []string

	data, err := h.ReadFile("/etc/login.defs")
	switch {
	case isNotExist(err):
		problems = append(problems, "/etc/login.defs missing")
	case err != nil:
		return errored(err)
	default:
		v := parseKeyValue(data)["umask"]
		if v == "" {
			problems = append(problems, "login.defs UMASK unset")
		} else if ok, err := umaskStrict(v); err != nil || !ok {
			problems = append(problems, "login.defs UMASK "+v)
		}
	}

	files := append([]string{}, umaskLocations...)
	if extra, err := h.Glob("/etc/profile.d/*.sh"); err == nil {
		files = append(files, extra...)
	}
	for _, f := range files {
		data, err := h.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "umask" {
				if ok, err := umaskStrict(fields[1]); err == nil && !ok {
					problems = append(problems, fmt.Sprintf("%s sets umask %s", f, fields[1]))
				}
			}
		}
	}

	if len(problems) > 0 {
		return fail("%s", joinLimited(problems, 4))
	}
	return pass("default umask is 027 or stricter")
}

func init() {
	register(
		fileModeCheck(Check{
			ID: "FILE-001", Title: "/etc/passwd permissions are 0644 or stricter", Control: "A.8.9", Severity: High,
			Remediation: "Run `chown root:root /etc/passwd && chmod 0644 /etc/passwd`",
		}, "/etc/passwd", 0o644, false),
		fileModeCheck(Check{
			ID: "FILE-002", Title: "/etc/shadow permissions are 0640 or stricter", Control: "A.8.9", Severity: Critical,
			Remediation: "Run `chown root:shadow /etc/shadow && chmod 0640 /etc/shadow` (root:root 0000 on RHEL)",
		}, "/etc/shadow", 0o640, false),
		fileModeCheck(Check{
			ID: "FILE-003", Title: "sshd_config permissions are 0600", Control: "A.8.9", Severity: Medium,
			Remediation: "Run `chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config`",
		}, sshdConfigPath, 0o600, true),
		Check{
			ID: "FILE-004", Title: "Default umask is 027 or stricter", Category: "Files", Control: "A.8.9", Severity: Low,
			Remediation: "Set `UMASK 027` in /etc/login.defs and `umask 027` in /etc/profile",
			run:         checkUmask,
		},
	)
}
