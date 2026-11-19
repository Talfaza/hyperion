#!/bin/sh
# TEST FIXTURE ONLY - this is not part of hyperion-trace, which is read-only.
#
# Installs the packages the baseline expects and applies the Hyperion
# hardening baseline (iso/hyperion.md, Part II) so the VM tests can check the
# scanner's pass paths. It changes the system it runs on, so it refuses to run
# anywhere except inside a throwaway test VM: a Ksar microVM, or a libvirt VM
# created with the SMBIOS serial "hyperion-test-vm". It is driven by the VM
# tests (`make vm-test`); do not run it by hand.
set -e

# ---- Guard: throwaway test VMs only -----------------------------------------
# Ksar: boots its own "-ksar" kernel AND writes the VM id to /run/ksar/id.
# libvirt: the test creates VMs with SMBIOS serial "hyperion-test-vm"
# (virt-install --sysinfo system.serial=...); the kernel exposes it in a
# root-only file. A real host has none of these markers.
in_test_vm=no
case "$(uname -r)" in
  *-ksar) [ -s /run/ksar/id ] && in_test_vm=yes ;;
esac
[ "$(cat /sys/class/dmi/id/product_serial 2>/dev/null)" = "hyperion-test-vm" ] && in_test_vm=yes
if [ "$in_test_vm" != yes ]; then
  echo "harden.sh: refusing to run: not a Ksar VM or a libvirt VM with serial hyperion-test-vm" >&2
  exit 99
fi

exec 3>&2
exec >/tmp/provision.log 2>&1
trap 'status=$?; [ $status -ne 0 ] && { echo "harden.sh failed (exit $status), last log lines:" >&3; tail -15 /tmp/provision.log >&3; }' EXIT

. /etc/os-release
case " $ID $ID_LIKE " in
  *" debian "*|*" ubuntu "*)
    export DEBIAN_FRONTEND=noninteractive
    # Fresh cloud VMs run unattended-upgrades at boot; wait for the dpkg lock.
    apt-get -o DPkg::Lock::Timeout=600 update -q
    apt-get -o DPkg::Lock::Timeout=600 install -y -q --no-install-recommends openssh-server sudo libpam-pwquality unattended-upgrades nftables
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    ;;
  *" fedora "*|*" rhel "*)
    # Enable timers by creating the symlink `systemctl enable` would: works
    # with and without a running systemd (is-enabled reads unit files).
    mkdir -p /etc/systemd/system/timers.target.wants
    if command -v dnf5 >/dev/null; then
      dnf -y -q --setopt=install_weak_deps=False install openssh-server sudo libpwquality dnf5-plugin-automatic nftables
      ln -sf /usr/lib/systemd/system/dnf5-automatic.timer /etc/systemd/system/timers.target.wants/dnf5-automatic.timer
      printf '[commands]\napply_updates = yes\n' > /etc/dnf/automatic.conf
    else
      # RHEL/Rocky 9: classic dnf-automatic with the install timer.
      dnf -y -q --setopt=install_weak_deps=False install openssh-server sudo libpwquality dnf-automatic nftables
      ln -sf /usr/lib/systemd/system/dnf-automatic-install.timer /etc/systemd/system/timers.target.wants/dnf-automatic-install.timer
    fi
    grep -q '^password.*pam_pwquality' /etc/pam.d/system-auth 2>/dev/null || \
      echo 'password requisite pam_pwquality.so retry=3' >> /etc/pam.d/system-auth
    ;;
  *" arch "*)
    pacman-key --init >/dev/null && pacman-key --populate archlinux >/dev/null
    # A full -Syu: installing single packages on an old image is a partial
    # upgrade, which pacman refuses (it once broke on OpenSSL 3 -> 4).
    pacman -Syu --noconfirm --needed openssh sudo libpwquality nftables
    # Arch ships pam_pwquality only as a commented example; enable it for real.
    grep -q '^password.*pam_pwquality' /etc/pam.d/passwd || \
      sed -i '1a password required pam_pwquality.so retry=3' /etc/pam.d/passwd
    ;;
  *) echo "unsupported distribution $ID"; exit 1 ;;
esac

# ---- SSH (A.8.2, A.8.24) ----------------------------------------------------
mkdir -p /etc/ssh/sshd_config.d /run/sshd
grep -q '^Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || \
  sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
# No mlkem768x25519-sha256: OpenSSH < 9.9 (Ubuntu 24.04, Debian 12) refuses it.
cat > /etc/ssh/sshd_config.d/00-hyperion-hardening.conf <<'EOF'
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
chmod 600 /etc/ssh/sshd_config
ssh-keygen -A
sshd -t

# ---- Accounts (A.8.2) -------------------------------------------------------
echo 'Defaults timestamp_timeout=5' > /etc/sudoers.d/hyperion && chmod 440 /etc/sudoers.d/hyperion
# Cloud images grant their default user passwordless sudo (Rocky writes it into
# /etc/sudoers itself). Require a password everywhere; the caller already holds
# a root shell.
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] && sed -i '/NOPASSWD/d' "$f"
done
visudo -c >/dev/null
cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF
useradd -D -f 30

# ---- Files (A.8.9) ----------------------------------------------------------
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
for f in /etc/profile /etc/bashrc /etc/bash.bashrc; do
  [ -f "$f" ] && sed -i 's/\bumask 0*22\b/umask 027/; s/\bumask 0*02\b/umask 027/' "$f"
done

# ---- Mounts (A.8.9) ---------------------------------------------------------
mount -t tmpfs -o nosuid,nodev,noexec tmpfs /tmp
mount -t tmpfs -o nosuid,nodev,noexec tmpfs /var/tmp
mount -o remount,nosuid,nodev,noexec /dev/shm 2>/dev/null || mount -t tmpfs -o nosuid,nodev,noexec tmpfs /dev/shm
mount --bind /var /var && mount -o remount,bind,nosuid,nodev /var
mount --bind /home /home && mount -o remount,bind,nosuid,nodev /home

# ---- Kernel (A.8.9): live values; keys the guest kernel lacks stay missing --
for kv in \
  kernel.dmesg_restrict=1 kernel.kptr_restrict=2 kernel.yama.ptrace_scope=1 \
  net.ipv4.tcp_syncookies=1 fs.protected_symlinks=1 fs.protected_hardlinks=1 fs.suid_dumpable=0 \
  net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 \
  net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.default.accept_redirects=0 \
  net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 \
  net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0 \
  net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 \
  net.ipv4.conf.all.accept_source_route=0 net.ipv4.conf.default.accept_source_route=0 \
  net.ipv6.conf.all.accept_source_route=0 net.ipv6.conf.default.accept_source_route=0 \
  net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
do
  k=${kv%%=*}; v=${kv#*=}; p=/proc/sys/$(echo "$k" | tr . /)
  if [ -w "$p" ]; then echo "$v" > "$p"; else echo "sysctl $k unavailable"; fi
done

# ---- Unneeded services (A.8.9) ----------------------------------------------
# Only with a running systemd (libvirt VMs); Ksar guests have none.
if [ -d /run/systemd/system ]; then
  for unit in rpcbind.service rpcbind.socket avahi-daemon.service avahi-daemon.socket cups.service cups.socket; do
    systemctl disable --now "$unit" 2>/dev/null || true
  done
fi

# ---- Firewall (A.8.9) -------------------------------------------------------
nft -f - <<'EOF' || echo "nftables unavailable in this kernel"
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport 22 accept
  }
}
EOF

# ---- Logging (A.8.15) -------------------------------------------------------
mkdir -p /var/log/journal
