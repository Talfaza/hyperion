package platform

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadFileSafeRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "sshd_config")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readFileSafe(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("want ErrNotRegular, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readFileSafe blocked on a FIFO")
	}
}

func TestReadFileSafeRejectsDirectoryAndDevice(t *testing.T) {
	if _, err := readFileSafe(t.TempDir()); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directory: want ErrNotRegular, got %v", err)
	}
	if _, err := readFileSafe("/dev/zero"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("/dev/zero: want ErrNotRegular, got %v", err)
	}
}

func TestReadFileSafeSizeLimit(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileSafe(big); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("want ErrFileTooLarge, got %v", err)
	}
	exact := filepath.Join(dir, "exact")
	if err := os.WriteFile(exact, make([]byte, MaxFileSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := readFileSafe(exact); err != nil || len(data) != MaxFileSize {
		t.Fatalf("file at the limit: len=%d err=%v", len(data), err)
	}
}

func TestHostPathCannotEscapeRoot(t *testing.T) {
	root := t.TempDir()
	h := &Host{Root: root}
	for _, p := range []string{"../../etc/passwd", "/../../etc/passwd", "/etc/../../../shadow", "etc/x"} {
		got := h.Path(p)
		if !strings.HasPrefix(got, root+string(os.PathSeparator)) {
			t.Errorf("Path(%q) = %q escapes root %q", p, got, root)
		}
	}
}

func TestGlobStripsRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/sudoers.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"b", "a"} {
		if err := os.WriteFile(filepath.Join(root, "etc/sudoers.d", n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := &Host{Root: root}
	got, err := h.Glob("/etc/sudoers.d/*")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "/etc/sudoers.d/a,/etc/sudoers.d/b" {
		t.Fatalf("got %v", got)
	}
}

func TestOSReleaseFamily(t *testing.T) {
	cases := map[string]Family{
		"ID=ubuntu\nID_LIKE=debian\n":                  FamilyDebian,
		"ID=debian\n":                                  FamilyDebian,
		"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"": FamilyRHEL,
		"ID=fedora\n":                                  FamilyRHEL,
		"ID=arch\n":                                    FamilyArch,
		"ID=manjaro\nID_LIKE=arch\n":                   FamilyArch,
		"ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"": FamilyUnknown,
	}
	for content, want := range cases {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := NewHost(root, &FakeRunner{}, true).OS.Family; got != want {
			t.Errorf("%q: family %s, want %s", content, got, want)
		}
	}
}

func TestLookupTrustedRejectsPaths(t *testing.T) {
	for _, name := range []string{"", "./sshd", "../bin/sh", "/usr/bin/id", "a/b"} {
		if _, err := lookupTrusted(name); err == nil {
			t.Errorf("lookupTrusted(%q) accepted a path", name)
		}
	}
	if _, err := lookupTrusted("definitely-not-a-real-binary-xyz"); !errors.Is(err, ErrCommandNotFound) {
		t.Errorf("missing binary: want ErrCommandNotFound, got %v", err)
	}
}

func TestLookupTrustedIgnoresPATH(t *testing.T) {
	// A malicious "id" first in PATH must not be picked up.
	evil := t.TempDir()
	if err := os.WriteFile(filepath.Join(evil, "id"), []byte("#!/bin/sh\necho pwned\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", evil+":"+os.Getenv("PATH"))
	got, err := lookupTrusted("id")
	if err != nil {
		t.Skipf("id not installed: %v", err)
	}
	if strings.HasPrefix(got, evil) {
		t.Fatalf("resolved %q from PATH", got)
	}
}

func TestVerifyTrustedRejectsNonRootOrWritable(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := verifyTrusted(bin); !errors.Is(err, ErrUntrustedBinary) {
			t.Fatalf("user-owned binary: want ErrUntrustedBinary, got %v", err)
		}
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := verifyTrusted(bin); !errors.Is(err, ErrUntrustedBinary) {
		t.Fatalf("world-writable binary: want ErrUntrustedBinary, got %v", err)
	}
	if err := verifyTrusted("/usr/bin/env"); err != nil {
		t.Fatalf("/usr/bin/env should be trusted: %v", err)
	}
}

func runnerFor(path string, timeout time.Duration) *ExecRunner {
	return &ExecRunner{Timeout: timeout, lookup: func(string) (string, error) { return path, nil }}
}

func TestExecRunnerDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("HYPERION_SECRET", "leak")
	res, err := runnerFor("/usr/bin/env", time.Second).Run(context.Background(), "env")
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout)
	for _, bad := range []string{"LD_PRELOAD", "HYPERION_SECRET"} {
		if strings.Contains(out, bad) {
			t.Errorf("child environment contains %s:\n%s", bad, out)
		}
	}
	if !strings.Contains(out, "PATH=/usr/sbin:/usr/bin:/sbin:/bin") || !strings.Contains(out, "LC_ALL=C") {
		t.Errorf("child environment missing safe defaults:\n%s", out)
	}
}

func TestExecRunnerTimeoutKillsProcess(t *testing.T) {
	start := time.Now()
	_, err := runnerFor("/usr/bin/sleep", 200*time.Millisecond).Run(context.Background(), "sleep", "30")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout error, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
}

func TestExecRunnerCapturesStderr(t *testing.T) {
	res, err := runnerFor("/usr/bin/ls", time.Second).Run(context.Background(), "ls", "/definitely/not/here")
	if err != nil || res.ExitCode == 0 || !strings.Contains(string(res.Stderr), "/definitely/not/here") {
		t.Fatalf("want stderr captured with non-zero exit, got %+v %v", res, err)
	}
}

func TestExecRunnerReportsExitCode(t *testing.T) {
	res, err := runnerFor("/usr/bin/false", time.Second).Run(context.Background(), "false")
	if err != nil || res.ExitCode != 1 {
		t.Fatalf("want exit 1 without error, got %+v %v", res, err)
	}
}

func TestExecRunnerOutputLimit(t *testing.T) {
	_, err := runnerFor("/usr/bin/head", 5*time.Second).Run(context.Background(), "head", "-c", "2000000", "/dev/zero")
	if err == nil || !strings.Contains(err.Error(), "output exceeded") {
		t.Fatalf("want output limit error, got %v", err)
	}
}

func TestMemoCachesErrors(t *testing.T) {
	h := &Host{}
	calls := 0
	fn := func() (any, error) { calls++; return nil, errors.New("boom") }
	for range 3 {
		if _, err := h.Memo("k", fn); err == nil {
			t.Fatal("want error")
		}
	}
	if calls != 1 {
		t.Fatalf("fn called %d times, want 1", calls)
	}
}

func FuzzParseEnvFile(f *testing.F) {
	f.Add([]byte("ID=\"ubuntu\"\nID_LIKE=debian\n# comment\n=bad\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseEnvFile(data)
	})
}

func TestLimitedBufferHasNoReadFrom(t *testing.T) {
	// io.Copy prefers ReaderFrom over Write; if limitedBuffer ever gains one,
	// the output cap is silently bypassed.
	var w any = &limitedBuffer{}
	if _, ok := w.(interface {
		ReadFrom(r io.Reader) (int64, error)
	}); ok {
		t.Fatal("limitedBuffer implements io.ReaderFrom, which bypasses the limit")
	}
}
