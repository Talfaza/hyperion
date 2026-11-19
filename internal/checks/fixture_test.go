package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/Talfaza/hyperion/internal/platform"
)

// fixture builds a fake host filesystem under a temp dir.
type fixture struct {
	t      *testing.T
	root   string
	run    *platform.FakeRunner
	asUser bool // scan as a non-root user
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{t: t, root: t.TempDir(), run: &platform.FakeRunner{}}
}

func (f *fixture) file(path, content string) *fixture {
	return f.fileMode(path, content, 0o644)
}

func (f *fixture) fileMode(path, content string, mode fs.FileMode) *fixture {
	f.t.Helper()
	full := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil { // bypass umask
		f.t.Fatal(err)
	}
	return f
}

func (f *fixture) dir(path string) *fixture {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(f.root, path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fixture) user() *fixture { f.asUser = true; return f }

// symlink creates path -> target inside the fixture (target is used as is).
func (f *fixture) symlink(path, target string) *fixture {
	f.t.Helper()
	full := filepath.Join(f.root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fixture) cmd(cmdline, stdout string, exit int) *fixture {
	f.run.Set(cmdline, stdout, exit)
	return f
}

func (f *fixture) debian() *fixture { return f.file("/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n") }
func (f *fixture) arch() *fixture   { return f.file("/etc/os-release", "ID=arch\n") }
func (f *fixture) rhel() *fixture {
	return f.file("/etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n")
}

func (f *fixture) host() *platform.Host {
	return platform.NewHost(f.root, f.run, !f.asUser)
}

// run executes check id against the fixture.
func (f *fixture) check(id string) Result {
	f.t.Helper()
	for _, c := range All() {
		if c.ID == id {
			return c.Run(context.Background(), f.host())
		}
	}
	f.t.Fatalf("no check %s", id)
	return Result{}
}

func expect(t *testing.T, id string, got Result, want Status) {
	t.Helper()
	if got.Status != want {
		t.Errorf("%s: status %s, want %s (detail: %s)", id, got.Status, want, got.Detail)
	}
}

type platformHost = platform.Host
