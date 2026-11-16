#!/bin/sh
# TEST FIXTURE ONLY - this is not part of hyperion-trace, which is read-only.
#
# Installs the packages the baseline expects and applies the Hyperion
# hardening baseline (iso/hyperion.md, Part II) so the VM tests can check the
# scanner's pass paths. It changes the system it runs on, so it refuses to run
# anywhere except inside a throwaway Ksar microVM. It is driven by vm_test.go
# (`make vm-test`); do not run it by hand.
set -e

# ---- Guard: Ksar VMs only ---------------------------------------------------
# Ksar writes the VM id to /run/ksar/id and boots its own "-ksar" kernel.
# Both must be present; a real host has neither.
case "$(uname -r)" in
  *-ksar) ;;
  *) echo "harden.sh: refusing to run: kernel $(uname -r) is not a Ksar guest kernel" >&2; exit 99 ;;
esac
if [ ! -s /run/ksar/id ]; then
  echo "harden.sh: refusing to run: /run/ksar/id missing, this is not a Ksar VM" >&2
  exit 99
fi

exec 3>&2
exec >/tmp/provision.log 2>&1
trap 'status=$?; [ $status -ne 0 ] && { echo "harden.sh failed (exit $status), last log lines:" >&3; tail -15 /tmp/provision.log >&3; }' EXIT

. /etc/os-release
case " $ID $ID_LIKE " in
  *" debian "*|*" ubuntu "*)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q --no-install-recommends openssh-server sudo libpam-pwquality unattended-upgrades nftables
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
    ;;
  *" fedora "*|*" rhel "*)
    dnf -y -q --setopt=install_weak_deps=False install openssh-server sudo libpwquality dnf5-plugin-automatic nftables
    # Enable the timer offline (is-enabled reads unit files) and apply updates.
    mkdir -p /etc/systemd/system/timers.target.wants
    ln -sf /usr/lib/systemd/system/dnf5-automatic.timer /etc/systemd/system/timers.target.wants/dnf5-automatic.timer
    printf '[commands]\napply_updates = yes\n' > /etc/dnf/automatic.conf
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

# ---- Firewall (A.8.9) -------------------------------------------------------
nft -f - <<'EOF' || echo "nftables unavailable in this kernel"
table inet filter {
  chain input { type filter hook input priority 0; policy drop; iif lo accept; }
}
EOF

# ---- Logging (A.8.15) -------------------------------------------------------
mkdir -p /var/log/journal
