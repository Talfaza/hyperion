// Package watch reports changes to watched files as they happen, using
// observe-only eBPF programs (fentry) that cannot block or alter anything.
//
// Milestone 1: writes, creations, renames, deletions and attribute changes
// (chmod, chown, truncate) under the watched directories, with who made them.
package watch

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event -type dir_key -type side watch bpf/watch.c -- -I/usr/include -O2 -g -Wall -Werror

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// DefaultPaths are watched when no --paths are given.
var DefaultPaths = []string{"/etc", "/boot", "/root/.ssh", "/usr/local/bin", "/usr/local/sbin"}

// Op is the kind of file operation observed.
type Op string

const (
	OpWrite  Op = "write"  // opened for writing
	OpCreate Op = "create" // created (and opened for writing)
	OpRename Op = "rename"
	OpDelete Op = "delete"
	OpChmod  Op = "chmod"
	OpChown  Op = "chown"
	OpTrunc  Op = "truncate"
)

// Event is one observed operation, attributed at the moment it happened.
type Event struct {
	Time time.Time `json:"time"`
	Op   Op        `json:"op"`
	Path string    `json:"path"`
	// From is the old path of a rename. It is "" when the file came from
	// outside the watched directories (e.g. `mv /tmp/x /etc/x`).
	From string `json:"from,omitempty"`
	// Mode, UID and GID are set for chmod and chown.
	Mode *uint32 `json:"mode,omitempty"`
	UID  uint32  `json:"uid"`
	EUID uint32  `json:"euid"`
	// LoginUID is the user who logged in, kept across sudo; nil when unset.
	LoginUID *uint32 `json:"login_uid,omitempty"`
	NewOwner *uint32 `json:"new_uid,omitempty"`
	NewGroup *uint32 `json:"new_gid,omitempty"`
	PID      uint32  `json:"pid"`
	PPID     uint32  `json:"ppid"`
	Comm     string  `json:"comm"`
	// Cmdline is read from /proc after the event, best effort: it is empty
	// when the process exited first.
	Cmdline string `json:"cmdline,omitempty"`
}

const (
	auditUIDUnset = 0xffffffff
	rootNone      = 0xffffffff
	attrMode      = 1 << 0
	attrUID       = 1 << 1
	attrGID       = 1 << 2
	attrSize      = 1 << 3
)

// ErrNotPrivileged is returned when the process cannot load eBPF programs.
var ErrNotPrivileged = errors.New("watch needs root (or CAP_BPF and CAP_PERFMON) to load its eBPF program")

// Options configure Run.
type Options struct {
	Paths []string // directories to watch; DefaultPaths when empty
	// Warn receives non-fatal problems (a missing path, a hook the kernel
	// can't support). It may be nil.
	Warn func(string)
	// Ready, if set, is called once every hook is attached: changes made
	// after it returns are reported.
	Ready func()
}

// Stats summarizes a run.
type Stats struct {
	Dropped uint64 // events lost because the ring buffer was full
}

// Run loads the eBPF programs and calls emit for every event until ctx is
// done.
func Run(ctx context.Context, opt Options, emit func(Event)) (Stats, error) {
	warn := opt.Warn
	if warn == nil {
		warn = func(string) {}
	}
	if os.Geteuid() != 0 {
		return Stats{}, ErrNotPrivileged
	}
	roots, keys, err := resolveRoots(opt.Paths, warn)
	if err != nil {
		return Stats{}, err
	}
	// Kernels before 5.11 charge BPF maps to RLIMIT_MEMLOCK.
	if err := rlimit.RemoveMemlock(); err != nil {
		return Stats{}, fmt.Errorf("raise memlock limit: %w", err)
	}

	spec, err := loadWatch()
	if err != nil {
		return Stats{}, fmt.Errorf("load eBPF spec: %w", err)
	}
	pid := os.Getpid()
	if pid <= 0 || pid > math.MaxUint32 {
		return Stats{}, fmt.Errorf("unexpected pid %d", pid)
	}
	if err := spec.Variables["self_pid"].Set(uint32(pid)); err != nil {
		return Stats{}, fmt.Errorf("configure eBPF program: %w", err)
	}
	// Attribute changes need notify_change(…, dentry, attr, …), the layout
	// since Linux 5.12. Never attach to a kernel where the arguments differ:
	// the program would read the wrong pointer.
	setattr := notifyChangeSupported()
	if !setattr {
		delete(spec.Programs, "on_setattr")
		warn("this kernel's notify_change has a different signature (Linux < 5.12): chmod, chown and truncate are not reported")
	}

	var objs watchObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return Stats{}, fmt.Errorf("load eBPF programs (kernel needs BTF and fentry support, 5.10+): %w", err)
	}
	defer objs.Close()

	for i, k := range keys {
		idx := uint32(i) // #nosec G115 -- len(keys) <= maxRoots
		if err := objs.Watched.Put(k, idx); err != nil {
			return Stats{}, fmt.Errorf("register %s: %w", roots[i], err)
		}
	}

	progs := []*ebpf.Program{objs.OnFileOpen, objs.OnRename, objs.OnUnlink}
	if setattr {
		progs = append(progs, objs.OnSetattr)
	}
	for _, p := range progs {
		lnk, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			return Stats{}, fmt.Errorf("attach %s: %w", p, err)
		}
		defer lnk.Close()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return Stats{}, fmt.Errorf("open ring buffer: %w", err)
	}
	defer rd.Close()
	if opt.Ready != nil {
		opt.Ready()
	}
	go func() {
		<-ctx.Done()
		_ = rd.Close() // unblocks Read; nothing useful to do on error
	}()

	// Kernel timestamps are CLOCK_MONOTONIC; anchor them to wall time once.
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return Stats{}, err
	}
	bootOffset := time.Now().Add(-time.Duration(ts.Nano()))

	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			return stats(&objs), fmt.Errorf("read ring buffer: %w", err)
		}
		var raw watchEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			continue // malformed record: skip, never crash
		}
		e, ok := decode(raw, roots, bootOffset)
		if !ok {
			continue
		}
		e.Cmdline = readCmdline(e.PID)
		emit(e)
	}
	return stats(&objs), nil
}

const maxRoots = 64 // size of the kernel's "watched" map

// resolveRoots turns watched paths into the (device, inode) keys the kernel
// matches on. Missing paths are skipped with a warning; symlinks are
// resolved so the real directory is watched.
func resolveRoots(paths []string, warn func(string)) ([]string, []watchDirKey, error) {
	if len(paths) == 0 {
		paths = DefaultPaths
	}
	var roots []string
	var keys []watchDirKey
	seen := map[watchDirKey]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return nil, nil, fmt.Errorf("watch path %q must be absolute", p)
		}
		real, err := filepath.EvalSymlinks(filepath.Clean(p))
		if err != nil {
			warn(fmt.Sprintf("not watching %s: %v", p, err))
			continue
		}
		var st unix.Stat_t
		if err := unix.Stat(real, &st); err != nil {
			warn(fmt.Sprintf("not watching %s: %v", p, err))
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return nil, nil, fmt.Errorf("watch path %s is not a directory", p)
		}
		key := watchDirKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
		if seen[key] {
			continue
		}
		seen[key] = true
		roots = append(roots, real)
		keys = append(keys, key)
	}
	if len(roots) == 0 {
		return nil, nil, errors.New("none of the watch paths exist")
	}
	if len(roots) > maxRoots {
		return nil, nil, fmt.Errorf("at most %d watch paths", maxRoots)
	}
	return roots, keys, nil
}

// kernelDev converts a userspace st_dev to the kernel's internal dev_t
// encoding (MKDEV: major << 20 | minor), which is what s_dev holds.
func kernelDev(dev uint64) uint32 {
	major, minor := unix.Major(dev), unix.Minor(dev)
	return major<<20 | minor&0xfffff
}

// notifyChangeSupported checks the running kernel's BTF: the second
// parameter of notify_change must be the dentry.
func notifyChangeSupported() bool {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return false
	}
	var fn *btf.Func
	if err := spec.TypeByName("notify_change", &fn); err != nil {
		return false
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	return ok && len(proto.Params) >= 3 && proto.Params[1].Name == "dentry" && proto.Params[2].Name == "attr"
}

// decode turns a kernel record into an Event. ok is false for a record that
// can't be right (a timestamp beyond int64 nanoseconds, an unknown watched
// root or operation).
func decode(raw watchEvent, roots []string, bootOffset time.Time) (Event, bool) {
	if raw.TimeNs > math.MaxInt64 {
		return Event{}, false
	}
	e := Event{
		Time: bootOffset.Add(time.Duration(raw.TimeNs)),
		UID:  raw.Uid,
		EUID: raw.Euid,
		PID:  raw.Pid,
		PPID: raw.Ppid,
		Comm: cString(raw.Comm[:]),
	}
	if raw.Loginuid != auditUIDUnset {
		v := raw.Loginuid
		e.LoginUID = &v
	}
	src, srcOK := sidePath(raw.Src, roots)
	dst, dstOK := sidePath(raw.Dst, roots)

	switch raw.Op {
	case 1:
		e.Op = OpWrite
	case 2:
		e.Op = OpCreate
	case 3:
		e.Op = OpRename
		if !dstOK && !srcOK {
			return Event{}, false
		}
		if dstOK {
			e.Path = dst
			if srcOK {
				e.From = src
			}
		} else {
			// Moved out of the watched directories: report the old path.
			e.Path = src
			e.From = src
			e.Op = OpDelete
		}
		return e, true
	case 4:
		e.Op = OpDelete
	case 5:
		switch {
		case raw.AttrValid&attrSize != 0:
			e.Op = OpTrunc
		case raw.AttrValid&(attrUID|attrGID) != 0:
			e.Op = OpChown
			if raw.AttrValid&attrUID != 0 {
				v := raw.AttrUid
				e.NewOwner = &v
			}
			if raw.AttrValid&attrGID != 0 {
				v := raw.AttrGid
				e.NewGroup = &v
			}
		default:
			e.Op = OpChmod
			v := raw.AttrMode & 0o7777
			e.Mode = &v
		}
	default:
		return Event{}, false
	}
	if !srcOK {
		return Event{}, false
	}
	e.Path = src
	return e, true
}

// sidePath rebuilds a path from its watched root and the name components
// the kernel collected (nearest the file first).
func sidePath(s watchSide, roots []string) (string, bool) {
	if s.Root == rootNone || int(s.Root) >= len(roots) || s.Depth == 0 {
		return "", false
	}
	n := int(s.Depth)
	stored := n
	if stored > len(s.Names) {
		stored = len(s.Names)
	}
	parts := make([]string, 0, stored+1)
	for i := stored - 1; i >= 0; i-- {
		name := cString(s.Names[i][:])
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return "", false // impossible directory entry name
		}
		parts = append(parts, name)
	}
	if n > stored {
		// Components above the deepest stored one were not recorded.
		parts = append([]string{"…"}, parts...)
	}
	return roots[s.Root] + "/" + strings.Join(parts, "/"), true
}

// readCmdline returns the process command line, or "" if it already exited.
func readCmdline(pid uint32) string {
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

func stats(objs *watchObjects) Stats {
	var n uint64
	_ = objs.Dropped.Lookup(uint32(0), &n)
	return Stats{Dropped: n}
}

// cString converts a NUL-terminated C byte array.
func cString(b []uint8) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
