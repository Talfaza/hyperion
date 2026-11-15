// Package platform gives checks read-only access to the host being audited.
//
// Every filesystem path is resolved against Host.Root, which is "/" in
// production and a fixture directory in tests. Commands go through Runner,
// which is a hardened exec wrapper in production and a fake in tests.
package platform

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Family groups distributions that share config layouts and tooling.
type Family string

const (
	FamilyDebian  Family = "debian"
	FamilyRHEL    Family = "rhel"
	FamilyUnknown Family = "unknown"
)

type OSInfo struct {
	ID         string
	PrettyName string
	VersionID  string
	Family     Family
}

type Host struct {
	Root     string
	Hostname string
	Kernel   string
	OS       OSInfo
	IsRoot   bool
	Run      Runner

	mu    sync.Mutex
	cache map[string]any
}

// NewLocalHost describes the machine the binary is running on.
func NewLocalHost() *Host {
	h := &Host{Root: "/", Run: NewExecRunner(), IsRoot: os.Geteuid() == 0}
	h.detect()
	return h
}

// NewHost builds a host rooted at an arbitrary directory, used by tests.
func NewHost(root string, run Runner, isRoot bool) *Host {
	h := &Host{Root: root, Run: run, IsRoot: isRoot}
	h.detect()
	return h
}

func (h *Host) detect() {
	h.OS = h.readOSRelease()
	if b, err := h.ReadFile("/proc/sys/kernel/hostname"); err == nil {
		h.Hostname = strings.TrimSpace(string(b))
	}
	if b, err := h.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
}

// Path maps an absolute host path into the host root. Cleaning the joined
// path keeps ".." components from escaping Root.
func (h *Host) Path(p string) string {
	return filepath.Join(h.Root, filepath.Clean("/"+p))
}

// Memo caches the result of an expensive lookup (e.g. `sshd -T`) so that
// several checks can share it within one scan.
func (h *Host) Memo(key string, fn func() (any, error)) (any, error) {
	type entry struct {
		v   any
		err error
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cache == nil {
		h.cache = map[string]any{}
	}
	if e, ok := h.cache[key]; ok {
		return e.(entry).v, e.(entry).err
	}
	v, err := fn()
	h.cache[key] = entry{v, err}
	return v, err
}

func (h *Host) readOSRelease() OSInfo {
	info := OSInfo{Family: FamilyUnknown}
	data, err := h.ReadFile("/etc/os-release")
	if err != nil {
		data, err = h.ReadFile("/usr/lib/os-release")
		if err != nil {
			return info
		}
	}
	kv := ParseEnvFile(data)
	info.ID = kv["ID"]
	info.PrettyName = kv["PRETTY_NAME"]
	info.VersionID = kv["VERSION_ID"]

	ids := strings.Fields(kv["ID"] + " " + kv["ID_LIKE"])
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			info.Family = FamilyDebian
			return info
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			info.Family = FamilyRHEL
			return info
		}
	}
	return info
}

// ParseEnvFile parses KEY=value lines (os-release, systemd env files),
// stripping matching surrounding quotes.
func ParseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}
