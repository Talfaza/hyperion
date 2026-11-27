//go:build vmtest && libvirt

// Full-distro tests in libvirt VMs: real systemd, AppArmor/SELinux, firewall
// services and time sync, which Ksar microVMs cannot provide. Run with
// `make vm-test-libvirt`.
//
// Each test boots an official cloud image (downloaded once into
// HYPERION_VM_CACHE, default ~/.cache/hyperion-vm, and checked against the
// distro's SHA-256 list), scans it stock, hardens it with harden.sh and scans
// again. The VM is created with SMBIOS serial "hyperion-test-vm", which is the
// marker harden.sh's guard accepts.
//
// VMs run in the user's libvirt session (no root daemon, no storage pool) with
// passt networking: guest traffic leaves through ordinary host sockets, so host
// firewall rules for bridged guests (e.g. Docker's FORWARD DROP) don't apply,
// and SSH reaches the guest through a forwarded localhost port. The disk is a
// copy-on-write overlay on the cached image. The VM, its overlay and its
// console log are always deleted afterwards.
package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	libvirtURI = "qemu:///session"
	vmSerial   = "hyperion-test-vm"
)

type cloudImage struct {
	name, family, osinfo string
	url, sumsURL         string
	sumLine              *regexp.Regexp // extracts the hex digest for the file
	// uefi boots with UEFI firmware. Rocky 9 cloud images do not boot with
	// the default legacy BIOS (nothing reaches the serial console).
	uefi bool
}

var cloudImages = []cloudImage{
	{
		name: "ubuntu", family: "debian", osinfo: "ubuntu24.04",
		url:     "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
		sumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS",
		sumLine: regexp.MustCompile(`(?m)^([0-9a-f]{64}) \*?noble-server-cloudimg-amd64\.img$`),
	},
	{
		name: "rocky", family: "rhel", osinfo: "rocky9",
		url:     "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2",
		sumsURL: "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM",
		sumLine: regexp.MustCompile(`(?m)^SHA256 \(Rocky-9-GenericCloud-Base\.latest\.x86_64\.qcow2\) = ([0-9a-f]{64})$`),
		uefi:    true,
	},
}

// libvirtTolerated are checks a hardened cloud VM may still not pass, with
// the reason. Everything else must pass. Only add entries backed by evidence.
var libvirtTolerated = map[string]string{
	// Cloud images are not LUKS-encrypted and a root disk cannot be encrypted
	// in place; real cloud servers use provider (KMS) encryption, recorded as
	// an exception. CRY-001 failing here is the correct verdict.
	"CRY-001": "cloud image root disks are not LUKS-encrypted (provider KMS encryption in production)",
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func virsh(t *testing.T, args ...string) string {
	return run(t, "virsh", append([]string{"-c", libvirtURI}, args...)...)
}

// fetch downloads url into dir once and verifies it against the distro's
// published SHA-256 list.
func fetch(t *testing.T, dir string, img cloudImage) string {
	t.Helper()
	dst := filepath.Join(dir, filepath.Base(img.url))
	resp, err := http.Get(img.sumsURL)
	if err != nil {
		t.Fatal(err)
	}
	sums, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	m := img.sumLine.FindSubmatch(sums)
	if m == nil {
		t.Fatalf("%s: no SHA-256 for %s in %s", img.name, filepath.Base(img.url), img.sumsURL)
	}
	want := string(m[1])

	if digest(t, dst) != want {
		t.Logf("downloading %s", img.url)
		resp, err := http.Get(img.url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		tmp := dst + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			t.Fatal(err)
		}
		f.Close()
		if got := digest(t, tmp); got != want {
			os.Remove(tmp)
			t.Fatalf("%s: SHA-256 mismatch: got %s want %s", img.name, got, want)
		}
		if err := os.Rename(tmp, dst); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func digest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// freePort asks the kernel for an unused localhost TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type testVM struct {
	t    *testing.T
	name string
	port int
	key  string
}

func (v *testVM) sshOpts() []string {
	return []string{"-i", v.key, "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5"}
}

// ssh runs cmd in the VM. On failure the error includes the command's stderr.
func (v *testVM) ssh(cmd string) (string, error) {
	args := append(v.sshOpts(), "-p", fmt.Sprint(v.port), "hyperion@127.0.0.1", cmd)
	c := exec.Command("ssh", args...)
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		err = fmt.Errorf("%w\n%s", err, stderr.String())
	}
	return string(out), err
}

func (v *testVM) scp(src, dst string) {
	v.t.Helper()
	args := append(append([]string{"-q", "-P", fmt.Sprint(v.port)}, v.sshOpts()...), src, "hyperion@127.0.0.1:"+dst)
	run(v.t, "scp", args...)
}

// boot creates the VM and registers its removal (VM, overlay, console log).
func boot(t *testing.T, img cloudImage, base, cache string) *testVM {
	t.Helper()
	name := "hyperion-test-" + img.name
	work := filepath.Join(cache, "run-"+img.name)
	undefine := func() {
		exec.Command("virsh", "-c", libvirtURI, "destroy", name).Run()
		exec.Command("virsh", "-c", libvirtURI, "undefine", name, "--nvram").Run()
		os.RemoveAll(work)
	}
	undefine() // leftovers from an interrupted run
	t.Cleanup(undefine)
	if err := os.MkdirAll(work, 0o700); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(work, "id_ed25519")
	run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", vmSerial, "-f", key)
	pub, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	userData := fmt.Sprintf(`#cloud-config
users:
  - name: hyperion
    groups: [wheel]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: true
    ssh_authorized_keys:
      - %s
ssh_pwauth: false
`, strings.TrimSpace(string(pub)))
	seedDir := filepath.Join(work, "seed")
	os.MkdirAll(seedDir, 0o755)
	os.WriteFile(filepath.Join(seedDir, "user-data"), []byte(userData), 0o644)
	os.WriteFile(filepath.Join(seedDir, "meta-data"), []byte("instance-id: "+name+"\nlocal-hostname: "+name+"\n"), 0o644)
	seedISO := filepath.Join(work, "seed.iso")
	run(t, "genisoimage", "-quiet", "-output", seedISO, "-volid", "cidata", "-joliet", "-rock",
		filepath.Join(seedDir, "user-data"), filepath.Join(seedDir, "meta-data"))

	disk := filepath.Join(work, "disk.qcow2")
	run(t, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, disk, "20G")
	console := filepath.Join(work, "console.log")

	v := &testVM{t: t, name: name, key: key, port: freePort(t)}
	var firmware []string
	if img.uefi {
		firmware = []string{"--boot", "uefi"}
	}
	run(t, "virt-install", append(firmware, "--connect", libvirtURI, "--import", "--name", name,
		"--memory", "2048", "--vcpus", "2",
		// Rocky/RHEL 9 need x86-64-v2; a generic CPU model will not boot them.
		"--cpu", "host-passthrough",
		"--disk", "path="+disk+",bus=virtio",
		"--disk", "path="+seedISO+",device=cdrom",
		"--network", fmt.Sprintf("type=user,backend.type=passt,model=virtio,"+
			"portForward0.proto=tcp,portForward0.range0.start=%d,portForward0.range0.to=22", v.port),
		"--serial", "file,path="+console,
		"--osinfo", "name="+img.osinfo+",require=off",
		"--sysinfo", "system.serial="+vmSerial,
		"--graphics", "none", "--noautoconsole")...)

	deadline := time.Now().Add(6 * time.Minute)
	for {
		if _, err := v.ssh("cloud-init status --wait >/dev/null 2>&1; true"); err == nil {
			return v
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(console)
			lines := strings.Split(string(log), "\n")
			t.Fatalf("SSH never came up; last console lines:\n%s", strings.Join(lines[max(0, len(lines)-40):], "\n"))
		}
		time.Sleep(3 * time.Second)
	}
}

// scan runs cmd (which must print one JSON report) and parses it.
func (v *testVM) scan(t *testing.T, cmd string) report {
	t.Helper()
	out, err := v.ssh(cmd)
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	return parse(t, []byte(out))
}

// waitTimeSync gives NTP time to converge on a freshly booted VM and logs
// the NTP client's own view if it does not.
func (v *testVM) waitTimeSync(t *testing.T) {
	for i := 0; i < 60; i++ {
		out, _ := v.ssh("timedatectl show -p NTPSynchronized --value")
		if strings.TrimSpace(out) == "yes" {
			return
		}
		time.Sleep(3 * time.Second)
	}
	out, _ := v.ssh("timedatectl status; timedatectl timesync-status 2>&1; chronyc tracking 2>&1; chronyc sources 2>&1; true")
	t.Logf("clock not synchronized after 3 min:\n%s", out)
}

func logNonPass(t *testing.T, label string, r report) {
	t.Helper()
	for _, f := range r.Findings {
		if f.Status != "pass" {
			t.Logf("%s %-5s %-8s %s", label, f.Status, f.ID, f.Detail)
		}
	}
	t.Logf("%s score %d", label, r.Score)
}

func TestLibvirt(t *testing.T) {
	for _, tool := range []string{"virsh", "virt-install", "qemu-img", "genisoimage", "ssh", "scp", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	if _, err := exec.LookPath("passt"); err != nil {
		t.Skip("passt not installed")
	}
	h := setup(t)
	home, _ := os.UserHomeDir()
	cache := env("HYPERION_VM_CACHE", filepath.Join(home, ".cache/hyperion-vm"))
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, img := range cloudImages {
		t.Run(img.name, func(t *testing.T) {
			base := fetch(t, cache, img)
			v := boot(t, img, base, cache)
			v.scp(h.bin, "/home/hyperion/hyperion-trace")
			v.scp(h.harden, "/home/hyperion/harden.sh")
			v.waitTimeSync(t)

			stock := v.scan(t, "sudo /home/hyperion/hyperion-trace scan --format json")
			sanity(t, stock)
			logNonPass(t, "stock", stock)
			if stock.Host.Family != img.family {
				t.Errorf("family %q, want %q", stock.Host.Family, img.family)
			}
			got := stock.byID()
			// The paths Ksar cannot exercise must produce real answers here.
			if got["MAC-001"].Status != "pass" {
				t.Errorf("MAC-001 on a stock %s: %s (%s), want pass (AppArmor/SELinux enforcing)", img.name, got["MAC-001"].Status, got["MAC-001"].Detail)
			}
			for _, id := range []string{"NET-002", "TIME-001", "SSH-001"} {
				if s := got[id].Status; s == "skip" || s == "error" {
					t.Errorf("%s: %s (%s), want a real verdict under systemd", id, s, got[id].Detail)
				}
			}

			// Every profile on the stock VM, with real systemd, SELinux or
			// AppArmor and running services.
			out, err := v.ssh("sudo sh -c " + shellQuote(profileScript("/home/hyperion/hyperion-trace")))
			if err != nil {
				t.Fatalf("profile scans: %v", err)
			}
			checkProfileInvariants(t, img.name+" stock", splitReports(t, out))

			// One root shell: harden, drop cloud-init's NOPASSWD rule (needed
			// only to get this shell), then scan.
			hard := v.scan(t, "sudo sh -c 'sh /home/hyperion/harden.sh && rm -f /etc/sudoers.d/90-cloud-init-users && /home/hyperion/hyperion-trace scan --format json'")
			sanity(t, hard)
			logNonPass(t, "hardened", hard)
			for _, f := range hard.Findings {
				if f.Status == "pass" {
					continue
				}
				if why, ok := libvirtTolerated[f.ID]; ok {
					t.Logf("tolerated %s: %s", f.ID, why)
					continue
				}
				t.Errorf("hardened %s: %s (%s), want pass", f.ID, f.Status, f.Detail)
			}
		})
	}
}

// shellQuote wraps s in single quotes for a remote shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// TestLibvirtWatch checks the experimental eBPF watcher on real kernels:
// every operation under the watched paths is reported with the right path,
// process and login user (including /boot, a separate mount on Rocky), and
// nothing outside them is.
func TestLibvirtWatch(t *testing.T) {
	for _, tool := range []string{"virsh", "virt-install", "qemu-img", "genisoimage", "ssh", "scp", "ssh-keygen", "passt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	h := setup(t)
	home, _ := os.UserHomeDir()
	cache := env("HYPERION_VM_CACHE", filepath.Join(home, ".cache/hyperion-vm"))
	for _, img := range cloudImages {
		t.Run(img.name, func(t *testing.T) {
			base := fetch(t, cache, img)
			v := boot(t, img, base, cache)
			v.scp(h.bin, "/home/hyperion/hyperion-trace")
			uidOut, err := v.ssh("id -u")
			if err != nil {
				t.Fatal(err)
			}
			loginUID := strings.TrimSpace(uidOut)
			kernel, _ := v.ssh("uname -r; findmnt -n -o SOURCE /boot || echo 'same fs as /'")

			out, err := v.ssh(`sudo sh -c '
F=/etc/hyperion-watch-test
/home/hyperion/hyperion-trace watch --format json --duration 30s > /tmp/watch.json 2> /tmp/watch.err &
W=$!
i=0; until grep -q "^ready" /tmp/watch.err; do i=$((i+1)); [ $i -gt 300 ] && break; sleep 0.1; done
echo hello >> $F
echo again >> $F
sed -i s/hello/world/ $F
echo staged > /tmp/hyperion-staged && mv /tmp/hyperion-staged /etc/hyperion-moved
chmod 600 $F
chown nobody $F
truncate -s 0 $F
mkdir -p /etc/hyperion-sub/deep && echo x > /etc/hyperion-sub/deep/file
touch /boot/hyperion-boot-test
cat /etc/hostname > /dev/null
echo ignored > /tmp/hyperion-not-watched
rm $F /etc/hyperion-moved /boot/hyperion-boot-test
rm -r /etc/hyperion-sub
sleep 1; kill -INT $W; wait $W
cat /tmp/watch.json; echo "=== stderr"; cat /tmp/watch.err'`)
			if err != nil {
				t.Fatalf("watch run: %v\n%s", err, out)
			}
			// The marker also appears inside events' cmdline (it is part of
			// this script), so split at its last occurrence.
			if i := strings.LastIndex(out, "=== stderr"); i >= 0 {
				if errOut := strings.TrimSpace(out[i+len("=== stderr"):]); errOut != "" {
					t.Logf("watch stderr: %s", errOut)
				}
				out = out[:i]
			}
			type ev struct {
				Op, Path, From, Comm string
				UID, EUID            uint32
				LoginUID             *uint32 `json:"login_uid"`
				Mode                 *uint32
				NewOwner             *uint32 `json:"new_uid"`
			}
			var events []ev
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				var e ev
				if line != "" && json.Unmarshal([]byte(line), &e) == nil {
					events = append(events, e)
				}
			}
			t.Logf("%s (kernel %s): %d events", img.name, strings.ReplaceAll(strings.TrimSpace(kernel), "\n", ", /boot on "), len(events))
			for _, e := range events {
				t.Logf("  %-8s %-40s from=%-24q comm=%-8s euid=%d login=%v", e.Op, e.Path, e.From, e.Comm, e.EUID, deref(e.LoginUID))
			}

			const f = "/etc/hyperion-watch-test"
			has := func(pred func(ev) bool) bool {
				for _, e := range events {
					if pred(e) {
						return true
					}
				}
				return false
			}
			want := map[string]func(ev) bool{
				"create by echo":           func(e ev) bool { return e.Op == "create" && e.Path == f && e.Comm == "sh" },
				"write by echo":            func(e ev) bool { return e.Op == "write" && e.Path == f && e.Comm == "sh" },
				"sed -i renames onto file": func(e ev) bool { return e.Op == "rename" && e.Path == f && strings.HasPrefix(e.From, "/etc/sed") },
				"mv from /tmp":             func(e ev) bool { return e.Op == "rename" && e.Path == "/etc/hyperion-moved" && e.From == "" },
				"chmod 600":                func(e ev) bool { return e.Op == "chmod" && e.Path == f && e.Mode != nil && *e.Mode == 0o600 },
				"chown nobody":             func(e ev) bool { return e.Op == "chown" && e.Path == f && e.NewOwner != nil && *e.NewOwner == 65534 },
				"truncate":                 func(e ev) bool { return e.Op == "truncate" && e.Path == f },
				"nested create":            func(e ev) bool { return e.Op == "create" && e.Path == "/etc/hyperion-sub/deep/file" },
				"/boot create":             func(e ev) bool { return e.Op == "create" && e.Path == "/boot/hyperion-boot-test" },
				"delete":                   func(e ev) bool { return e.Op == "delete" && e.Path == f },
			}
			for name, pred := range want {
				if !has(pred) {
					t.Errorf("missing: %s", name)
				}
			}
			for _, e := range events {
				if !strings.HasPrefix(e.Path, "/etc/") && !strings.HasPrefix(e.Path, "/boot/") {
					t.Errorf("event outside watched paths: %s %s", e.Op, e.Path)
				}
				if e.Path == "/etc/hostname" {
					t.Error("a read of /etc/hostname was reported")
				}
				if e.Comm == "sh" && e.Path == f && (e.EUID != 0 || e.LoginUID == nil || fmt.Sprint(*e.LoginUID) != loginUID) {
					t.Errorf("attributed to euid %d login %v, want euid 0 login %s", e.EUID, deref(e.LoginUID), loginUID)
				}
			}
		})
	}
}

func deref(p *uint32) any {
	if p == nil {
		return "unset"
	}
	return *p
}
