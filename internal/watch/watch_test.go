package watch

import (
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCString(t *testing.T) {
	cases := map[string][]uint8{
		"":         {0, 'x'},
		"bash":     {'b', 'a', 's', 'h', 0, 'z', 'z'},
		"no-nul":   []uint8("no-nul"),
		"/etc/ssh": append([]uint8("/etc/ssh"), make([]uint8, 10)...),
	}
	for want, in := range cases {
		if got := cString(in); got != want {
			t.Errorf("cString(%q) = %q, want %q", in, got, want)
		}
	}
}

// side builds a kernel-style side: names are given file-first, as the
// eBPF walk records them.
func side(root uint32, names ...string) watchSide {
	var s watchSide
	s.Root = root
	s.Depth = uint32(len(names))
	for i, n := range names {
		if i < len(s.Names) {
			copy(s.Names[i][:], n)
		}
	}
	return s
}

var roots = []string{"/etc", "/boot"}

func rawEvent(op uint32) watchEvent {
	var raw watchEvent
	raw.TimeNs = uint64(5 * time.Second)
	raw.Op = op
	raw.Pid, raw.Ppid, raw.Uid, raw.Euid, raw.Loginuid = 42, 41, 0, 0, 1000
	copy(raw.Comm[:], "sed")
	raw.Src = side(rootNone)
	raw.Dst = side(rootNone)
	return raw
}

func TestSidePath(t *testing.T) {
	if p, ok := sidePath(side(0, "sshd_config", "ssh"), roots); !ok || p != "/etc/ssh/sshd_config" {
		t.Errorf("got %q %v", p, ok)
	}
	if p, ok := sidePath(side(1, "grub.cfg", "grub2"), roots); !ok || p != "/boot/grub2/grub.cfg" {
		t.Errorf("separate mount root: got %q %v", p, ok)
	}
	deep := side(0, "f", "a", "b", "c", "d", "e", "g", "h", "i", "j")
	deep.Depth = 14 // more levels than the kernel stores
	if p, ok := sidePath(deep, roots); !ok || !strings.HasPrefix(p, "/etc/…/") {
		t.Errorf("elided path: got %q %v", p, ok)
	}
	for name, s := range map[string]watchSide{
		"no root":    side(rootNone, "x"),
		"bad root":   side(7, "x"),
		"empty":      side(0),
		"dotdot":     side(0, ".."),
		"slash":      side(0, "a/b"),
		"empty name": side(0, ""),
	} {
		if p, ok := sidePath(s, roots); ok {
			t.Errorf("%s: accepted as %q", name, p)
		}
	}
}

func TestDecodeOps(t *testing.T) {
	boot := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

	w := rawEvent(1)
	w.Src = side(0, "hosts")
	e, ok := decode(w, roots, boot)
	if !ok || e.Op != OpWrite || e.Path != "/etc/hosts" || e.Comm != "sed" || e.PPID != 41 || *e.LoginUID != 1000 {
		t.Fatalf("write: %+v %v", e, ok)
	}
	if !e.Time.Equal(boot.Add(5 * time.Second)) {
		t.Errorf("time %v", e.Time)
	}

	r := rawEvent(3)
	r.Src = side(0, "sedAbC123")
	r.Dst = side(0, "hosts")
	if e, ok := decode(r, roots, boot); !ok || e.Op != OpRename || e.Path != "/etc/hosts" || e.From != "/etc/sedAbC123" {
		t.Errorf("rename within watched: %+v %v", e, ok)
	}
	r.Src = side(rootNone, "x") // mv /tmp/x /etc/hosts
	if e, ok := decode(r, roots, boot); !ok || e.Path != "/etc/hosts" || e.From != "" {
		t.Errorf("rename into watched: %+v %v", e, ok)
	}
	r.Src, r.Dst = side(0, "hosts"), side(rootNone, "x") // mv /etc/hosts /tmp/x
	if e, ok := decode(r, roots, boot); !ok || e.Op != OpDelete || e.Path != "/etc/hosts" {
		t.Errorf("rename out of watched: %+v %v", e, ok)
	}

	a := rawEvent(5)
	a.Src = side(0, "shadow")
	a.AttrValid, a.AttrMode = attrMode, 0o100644
	if e, ok := decode(a, roots, boot); !ok || e.Op != OpChmod || *e.Mode != 0o644 {
		t.Errorf("chmod: %+v %v", e, ok)
	}
	a.AttrValid, a.AttrUid, a.AttrGid = attrUID|attrGID, 1000, 1000
	if e, ok := decode(a, roots, boot); !ok || e.Op != OpChown || *e.NewOwner != 1000 || *e.NewGroup != 1000 {
		t.Errorf("chown: %+v %v", e, ok)
	}
	a.AttrValid = attrSize
	if e, ok := decode(a, roots, boot); !ok || e.Op != OpTrunc {
		t.Errorf("truncate: %+v %v", e, ok)
	}

	bad := rawEvent(1) // no watched root
	if _, ok := decode(bad, roots, boot); ok {
		t.Error("event outside watched roots accepted")
	}
	bad = rawEvent(99)
	bad.Src = side(0, "x")
	if _, ok := decode(bad, roots, boot); ok {
		t.Error("unknown op accepted")
	}
	bad = rawEvent(1)
	bad.Src = side(0, "x")
	bad.TimeNs = math.MaxInt64 + 1
	if _, ok := decode(bad, roots, boot); ok {
		t.Error("impossible timestamp accepted")
	}
	bad.TimeNs = 1
	bad.Loginuid = auditUIDUnset
	if e, _ := decode(bad, roots, boot); e.LoginUID != nil {
		t.Error("unset login uid should decode to nil")
	}
}

func TestKernelDev(t *testing.T) {
	// 8:3 (e.g. /dev/sda3) and a minor above 255 (encoding differs from st_dev).
	if got := kernelDev(unix.Mkdev(8, 3)); got != 8<<20|3 {
		t.Errorf("8:3 -> %#x", got)
	}
	if got := kernelDev(unix.Mkdev(259, 300)); got != 259<<20|300 {
		t.Errorf("259:300 -> %#x", got)
	}
}

func TestResolveRoots(t *testing.T) {
	dir := t.TempDir()
	var warnings []string
	roots, keys, err := resolveRoots([]string{dir, dir, dir + "/missing"}, func(s string) { warnings = append(warnings, s) })
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || len(keys) != 1 {
		t.Errorf("duplicates should collapse: %v", roots)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "missing") {
		t.Errorf("missing path should warn: %v", warnings)
	}
	if _, _, err := resolveRoots([]string{"relative/path"}, func(string) {}); err == nil {
		t.Error("relative path accepted")
	}
	if _, _, err := resolveRoots([]string{dir + "/missing"}, func(string) {}); err == nil {
		t.Error("no existing path should be an error")
	}
}
