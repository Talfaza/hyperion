package checks

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Talfaza/hyperion/internal/platform"
)

// blockDevice maps a mount source such as /dev/nvme0n1p2, /dev/dm-0 or
// /dev/mapper/luks-xyz to its kernel block device name (nvme0n1p2, dm-0).
func blockDevice(h *platform.Host, source string) (string, bool) {
	if !strings.HasPrefix(source, "/dev/") {
		return "", false
	}
	name := path.Base(source)
	if target, err := h.Readlink(source); err == nil {
		name = path.Base(target)
	}
	if !h.Exists("/sys/class/block/" + name) {
		return "", false
	}
	return name, true
}

const maxDeviceDepth = 8

// dmCrypt reports whether block device name is, or sits on top of, a
// dm-crypt mapping. It walks the device-mapper stack through sysfs, so
// LVM-on-LUKS and similar layouts are recognized.
func dmCrypt(h *platform.Host, name string, depth int) bool {
	if depth > maxDeviceDepth {
		return false
	}
	if uuid, err := h.ReadFile("/sys/class/block/" + name + "/dm/uuid"); err == nil &&
		strings.HasPrefix(strings.TrimSpace(string(uuid)), "CRYPT-") {
		return true
	}
	slaves, _ := h.Glob("/sys/class/block/" + name + "/slaves/*")
	for _, s := range slaves {
		if dmCrypt(h, path.Base(s), depth+1) {
			return true
		}
	}
	return false
}

// virtualFS are filesystems that are not backed by a disk of this host.
var virtualFS = map[string]bool{"overlay": true, "tmpfs": true, "rootfs": true, "zfs": true, "nfs": true, "nfs4": true, "9p": true, "virtiofs": true}

func checkRootEncrypted(_ context.Context, h *platform.Host) Result {
	data, err := h.ReadFile("/proc/self/mounts")
	if err != nil {
		return errored(err)
	}
	root, ok := parseMounts(data)["/"]
	if !ok {
		return errored(fmt.Errorf("no root filesystem in /proc/self/mounts"))
	}
	if virtualFS[root.fstype] {
		return skip("root filesystem is %s, not a local disk (container or network root?)", root.fstype)
	}
	dev, ok := blockDevice(h, root.source)
	if !ok {
		return errored(fmt.Errorf("cannot map root device %s to a kernel block device", root.source))
	}
	if dmCrypt(h, dev, 0) {
		return pass("root filesystem (%s) is on dm-crypt", root.source)
	}
	return fail("root filesystem (%s) is not on dm-crypt/LUKS; if the cloud provider encrypts the volume (KMS), record that as an exception", root.source)
}

// swapArea is one line of /proc/swaps.
type swapArea struct {
	name, kind string
}

func parseSwaps(data []byte) []swapArea {
	var out []swapArea
	for i, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 2 {
			continue // header
		}
		out = append(out, swapArea{name: unescapeMount(f[0]), kind: f[1]})
	}
	return out
}

// mountFor returns the mount holding path (longest matching mount point).
func mountFor(mounts map[string]mountEntry, p string) (mountEntry, bool) {
	var best mountEntry
	found := false
	for point, m := range mounts {
		if (p == point || strings.HasPrefix(p, strings.TrimSuffix(point, "/")+"/")) && len(point) >= len(best.point) {
			best, found = m, true
		}
	}
	return best, found
}

func checkSwapEncrypted(_ context.Context, h *platform.Host) Result {
	data, err := h.ReadFile("/proc/swaps")
	if err != nil {
		return errored(err)
	}
	areas := parseSwaps(data)
	if len(areas) == 0 {
		return pass("no swap is configured")
	}
	mountData, err := h.ReadFile("/proc/self/mounts")
	if err != nil {
		return errored(err)
	}
	mounts := parseMounts(mountData)

	var plain []string
	for _, a := range areas {
		switch {
		case strings.HasPrefix(a.name, "/dev/zram"):
			continue // compressed RAM, never written to disk
		case a.kind == "file":
			m, ok := mountFor(mounts, a.name)
			if !ok || virtualFS[m.fstype] {
				continue
			}
			if dev, ok := blockDevice(h, m.source); ok && dmCrypt(h, dev, 0) {
				continue
			}
			plain = append(plain, a.name)
		default:
			if dev, ok := blockDevice(h, a.name); ok && dmCrypt(h, dev, 0) {
				continue
			}
			plain = append(plain, a.name)
		}
	}
	if len(plain) > 0 {
		return fail("unencrypted swap: %s", joinLimited(plain, 3))
	}
	return pass("all swap is encrypted or RAM-backed (zram)")
}

func init() {
	register(
		Check{
			ID: "CRY-001", Title: "Root filesystem is encrypted (LUKS)", Category: "Crypto", Control: "A.8.24", Severity: Medium,
			Remediation: "Install on a LUKS2-encrypted volume (cryptsetup), or use provider KMS-backed volume encryption and record it as an exception",
			run:         checkRootEncrypted,
		},
		Check{
			ID: "CRY-002", Title: "Swap is encrypted or RAM-backed", Category: "Crypto", Control: "A.8.24", Severity: Medium,
			Remediation: "Put swap on a LUKS volume (or random-key dm-crypt via /etc/crypttab), switch to zram, or disable swap",
			run:         checkSwapEncrypted,
		},
	)
}
