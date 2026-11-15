package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// TrustedDirs are the only directories commands are resolved from. $PATH is
// never consulted, so a writable directory early in PATH cannot shadow sshd.
var TrustedDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// safeEnv is the complete environment given to child processes. Nothing is
// inherited from the caller (no LD_PRELOAD, no PATH, no locale surprises).
var safeEnv = []string{
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	"LC_ALL=C",
	"LANG=C",
	"SYSTEMD_PAGER=",
	"SYSTEMD_COLORS=0",
}

const (
	DefaultCommandTimeout = 10 * time.Second
	maxCommandOutput      = 1 << 20
)

var (
	ErrCommandNotFound = errors.New("command not found in trusted directories")
	ErrUntrustedBinary = errors.New("binary is not owned by root or is writable by others")
)

// CmdResult is the outcome of a command that was started successfully.
// A non-zero exit code is not an error: tools like `systemctl is-active` and
// `needs-restarting -r` use exit codes to report state.
type CmdResult struct {
	Stdout   []byte
	ExitCode int
}

// Runner executes read-only inspection commands.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (CmdResult, error)
}

// ExecRunner runs real commands with a hardened execution policy.
type ExecRunner struct {
	Timeout time.Duration
	// lookup is overridable in tests.
	lookup func(name string) (string, error)
}

func NewExecRunner() *ExecRunner {
	return &ExecRunner{Timeout: DefaultCommandTimeout, lookup: lookupTrusted}
}

func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	path, err := r.lookup(name)
	if err != nil {
		return CmdResult{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	var stdout limitedBuffer
	stdout.limit = maxCommandOutput

	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- path is resolved from TrustedDirs, args are constants
	cmd.Env = safeEnv
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	// Run in its own process group so a timeout kills any children too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second

	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return CmdResult{}, fmt.Errorf("%s: timed out after %s", name, r.Timeout)
	}
	if stdout.truncated {
		return CmdResult{}, fmt.Errorf("%s: output exceeded %d bytes", name, maxCommandOutput)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return CmdResult{Stdout: stdout.Bytes(), ExitCode: exitErr.ExitCode()}, nil
	}
	if err != nil {
		return CmdResult{}, fmt.Errorf("%s: %w", name, err)
	}
	return CmdResult{Stdout: stdout.Bytes()}, nil
}

// lookupTrusted resolves a bare command name inside TrustedDirs and verifies
// the resolved binary is root-owned and not group/world writable.
func lookupTrusted(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("%q: command must be a bare name", name)
	}
	for _, dir := range TrustedDirs {
		candidate := filepath.Join(dir, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if err := verifyTrusted(resolved); err != nil {
			return "", fmt.Errorf("%s: %w", resolved, err)
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%s: %w", name, ErrCommandNotFound)
}

func verifyTrusted(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("not an executable regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return ErrUntrustedBinary
	}
	return nil
}

// limitedBuffer stops accepting data past limit but keeps the writer happy so
// the child does not get SIGPIPE mid-write. The buffer is a named field, not
// embedded: embedding bytes.Buffer would promote ReadFrom, and io.Copy would
// use it and bypass the limit entirely.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if len(p) > room {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }
