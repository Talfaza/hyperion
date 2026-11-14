
# Hyperion: Continuous Linux Security Auditing & Configuration Drift Platform

---

## Part I: Product, Architecture & Business Blueprint

### 1. Executive Summary & Market Positioning
**Hyperion** is a unified Linux Security Auditing and Configuration Drift Detection SaaS platform built for modern cloud, hybrid, and bare-metal infrastructure. 

While traditional Infrastructure-as-Code (IaC) and GitOps tools manage Kubernetes manifests, the underlying Linux host operating systems remain blind spots—vulnerable to 3:00 AM manual SSH hotfixes, configuration decay, and compliance drift. By combining real-time drift detection with automated **ISO/IEC 27001:2022**, **SOC 2**, **PCI-DSS**, and **NIS2** security auditing, Hyperion turns manual compliance preparation into continuous, automated verification.

* **Core Mission:** Deliver zero-overhead, kernel-level visibility into every configuration change and security posture deviation across Linux fleets.
* **Open-Core Brand Architecture:**
  * **Hyperion Trace:** The open-source, lightweight eBPF agent deployed on customer Linux nodes.
  * **Hyperion State:** The commercial SaaS control plane, drift correlation engine, alerting hub, and compliance reporting dashboard.

---

### 2. System Architecture

```text
+-----------------------------------------------------------------------+
|                       HYPERION TRACE (Linux Host)                     |
|                                                                       |
|  +---------------------------------+  +----------------------------+  |
|  |   eBPF Kernel Probes (Ring 0)   |  |  Continuous Posture Engine |  |
|  |  (openat, write, execve, chmod) |  |  (ISO 27001 / CIS Checks)  |  |
|  +----------------+----------------+  +-------------+--------------+  |
|                   |                                 |                 |
|                   +----------------+----------------+                 |
|                                    v                                  |
|  +-----------------------------------------------------------------+  |
|  |         Local Secret Redaction & Path Exclusion Engine          |  |
|  |     (Strips API keys, passwords & private keys before egress)   |  |
|  +---------------------------------+-------------------------------+  |
|                                    |                                  |
|                                    v                                  |
|  +-----------------------------------------------------------------+  |
|  |               mTLS Telemetry & Diff Emitter (Go)                |  |
|  +---------------------------------+-------------------------------+  |
+------------------------------------|----------------------------------+
                                     | (TLS 1.3 / mTLS Diffs Only)
                                     v
+-----------------------------------------------------------------------+
|                       HYPERION STATE (SaaS Cloud)                     |
|                                                                       |
|  +-------------------+    +-------------------+    +---------------+  |
|  |   Ingestion API   |--->|   Message Queue   |--->| Change & Rule |  |
|  |   (Go / Rust)     |    |  (Redis / Kafka)  |    |   Processor   |  |
|  +-------------------+    +-------------------+    +-------+-------+  |
|                                                            |          |
|         +--------------------------------------------------+          |
|         |                          |                       |          |
|         v                          v                       v          |
|  +--------------+       +--------------------+    +----------------+  |
|  | Golden Node  |       |   Storage Layer    |    | Alerting Hub   |  |
|  | & GitOps     |       | - PostgreSQL       |    | - Slack/Teams  |  |
|  | Diff Engine  |       | - S3 Diff Store    |    | - PagerDuty    |  |
|  +--------------+       +--------------------+    +----------------+  |
|                                    |                                  |
|                                    v                                  |
|  +-----------------------------------------------------------------+  |
|  |    Web Dashboard (Next.js): Diff Viewer, Posture Score & PDF    |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------------------------------------------+
```

#### 2.1 Hyperion Trace (Open-Source Edge Agent)
* **Event-Driven eBPF Probes (C + Go):** Attaches to kernel tracepoints (`sys_enter_openat`, `sys_enter_write`, `sys_enter_execve`, `sys_enter_chmod`, `sys_enter_setuid`). Instead of CPU-heavy file polling or complex `auditd` rules, the agent sleeps until watched paths (`/etc/`, `/boot/`, `/usr/local/bin/`, `/var/lib/`) are modified, capturing exact attribution (`PID`, `UID`, binary path, and command arguments) in milliseconds.
* **Continuous Posture & Hardening Scanner:** Periodically evaluates host state against the ISO/IEC 27001:2022 & CIS baseline (Section II of this document) to compute a live `0-100%` security score per node.
* **Local Secret Redaction:** Uses regex patterns and Shannon entropy detection on-host to redact passwords, private keys, and tokens before serialization. Sensitive secrets are hashed (`SHA-256` with local salt) so Hyperion State detects changes without ever receiving raw credentials.

#### 2.2 Hyperion State (SaaS Control Plane)
* **Decoupled Ingestion Pipeline:** An mTLS-authenticated Ingestion API pushes incoming node events into a Redis/Kafka queue, preventing database contention during fleet-wide deployments.
* **Baseline & GitOps Reconciliation Engine:** Compares live node configurations against either a designated **"Golden Server"** baseline or the customer's GitHub/GitLab Infrastructure-as-Code (Terraform/Ansible) repositories.
* **Actionable Alerting & One-Click Remediation:** Sends rich Slack, Microsoft Teams, or PagerDuty alerts with side-by-side diffs, attribution, and one-click options to **Revert** the file or **Approve as Hotfix** (automatically opening a Git Pull Request).
* **Compliance Evidence Generator:** Exports tamper-evident audit trails and posture reports mapped directly to ISO 27001, SOC 2, and PCI-DSS controls.

---

### 3. Security & Zero-Trust Architecture
* **Read-Only Kernel Observation:** eBPF probes operate strictly in read-only observation mode by default; active syscall blocking or rollback is opt-in only.
* **Transport Security:** All agent-to-cloud communication enforces **TLS 1.3 with Mutual TLS (mTLS)** and rotating cryptographic agent tokens.
* **Data Minimization:** Full disk snapshots are never uploaded—only redacted configuration diffs, metadata, and posture check statuses are stored.
* **Cloud Hardening:** Backend databases run inside isolated private VPC subnets encrypted at rest with AES-256.

---

### 4. Go-to-Market (GTM) & Monetization Strategy

#### Phase 1: The Managed DevSecOps "Trojan Horse" (Local SMEs & Regional FinTech)
* **Strategy:** Small businesses rarely buy standalone configuration drift software, but they urgently need security hardening and audit readiness. Offer a monthly **"Continuous Linux Security & Hardening Retainer"** to local SMEs, FinTech startups, and government contractors.
* **Execution:** Deploy Hyperion Trace as your proprietary operational tool to harden their servers, monitor for unauthorized changes, and deliver monthly executive security reports. This generates immediate cash flow while battle-testing the platform in production.

#### Phase 2: Open Core & Global Self-Serve SaaS (Compliance-Driven)
* **Strategy:** Open-source **Hyperion Trace** on GitHub (Apache 2.0) to build trust with SysAdmins and DevOps engineers. Market **Hyperion State** globally around the **"Compliance Trigger"**—targeting companies preparing for ISO 27001, SOC 2 Type II, PCI-DSS, or EU NIS2/DORA audits.

#### Pricing Tiers (Per-Node SaaS Model)

| Tier | Price | Target Audience | Included Capabilities |
| :--- | :--- | :--- | :--- |
| **Developer (Open Source)** | **$0 / month** | Homelabs, Solo SysAdmins | Up to 5 nodes, local eBPF CLI alerts, basic posture checks, 7-day retention. |
| **Growth** | **$15 / node / month** | Tech Startups, Mid-Market | Up to 100 nodes, Slack/Teams/PagerDuty alerts, GitOps sync, 90-day retention. |
| **Enterprise** | **$40+ / node / month** | FinTech, Healthcare, Gov | Unlimited nodes, 1-year+ retention, automated ISO 27001/SOC 2 PDF exports, auto-remediation, SSO/RBAC. |

---
---

## Part II: Modernized Linux System Hardening & Audit Baseline (ISO/IEC 27001:2022)

This standard updates legacy Linux hardening procedures to eliminate deprecated tooling, prevent modern distribution breakage, and align accurately with **ISO/IEC 27001:2022 Annex A** controls. Hyperion Trace uses these exact rules as its automated auditing baseline.

### Changelog: Legacy Guide Corrections & Modernization
Before applying the baseline, note the following critical updates over legacy hardening guides:
1. **Replaced `yum-cron` with `dnf-automatic`:** `yum-cron` is deprecated and removed in RHEL 8/9/10, Rocky Linux, AlmaLinux, and Fedora.
2. **Modernized Logging (`systemd-journald`):** Minimal Debian 12+, Ubuntu 24.04+, and RHEL 8/9/10 builds do not install `rsyslog` by default; `/var/log/auth.log` may not exist unless explicitly configured. Auditing must inspect `journald` alongside optional `rsyslog` forwarding.
3. **Removed "SSL" References:** SSLv2/v3 and TLS 1.0/1.1 are insecure and prohibited. Only **TLS 1.2 and TLS 1.3** are permitted.
4. **Fixed `/var` Mount Options:** Mounting `/var` with `noexec` breaks `apt`/`dpkg`, `rpm` scriptlets, Snap/Flatpak, and container runtimes (`/var/lib/docker`, `/var/lib/containerd`). Apply `noexec,nosuid,nodev` to `/tmp`, `/var/tmp`, and `/dev/shm`, and **`nosuid,nodev` only** to `/var`.
5. **Replaced Periodic Antivirus Scans with FIM & Runtime eBPF:** Scheduled ClamAV disk scans are obsolete for general Linux servers (reserved only for mail/upload gateways). Modern servers require File Integrity Monitoring (FIM) and eBPF behavioral execution auditing.
6. **Corrected ISO/IEC 27001:2022 Annex A Mappings:** Fixed mislabeled controls (`A.8.7` for Malware, `A.8.8` for Vulnerability/Patch Management, `A.8.9` for Configuration Management) and added **Time Synchronization (`A.8.17`)**, **Kernel `sysctl` hardening**, and **Mandatory Access Control (SELinux/AppArmor)**.

---

### 1. Scope & Control Mapping
This baseline defines mandatory hardening and continuous audit controls for all production and staging Linux servers (Debian/Ubuntu and RHEL/Rocky/AlmaLinux/Fedora) in accordance with **ISO/IEC 27001:2022 Annex A**:

* **A.8.2** — Privileged access rights
* **A.8.7** — Protection against malware
* **A.8.8** — Management of technical vulnerabilities
* **A.8.9** — Configuration management
* **A.8.15** — Logging
* **A.8.16** — Monitoring activities
* **A.8.17** — Clock synchronization
* **A.8.24** — Use of cryptography
* **A.5.36** — Compliance with policies, rules and standards for information security

---

### 2. Objective
To enforce confidentiality, integrity, and availability across Linux infrastructure by minimizing attack surfaces, eliminating unauthorized configuration drift, and maintaining tamper-evident audit trails.

---

### 3. Roles and Responsibilities
* **System Administrator / DevOps:** Implements hardening baselines via Infrastructure-as-Code (Ansible/Terraform) and remediates detected drift.
* **Security Officer:** Defines baseline policies, reviews Hyperion State compliance scores, and approves documented exceptions.
* **Audit Team:** Verifies continuous adherence through tamper-evident logs and periodic compliance reports.

---

### 4. Access Control (`A.8.2`)
* **Disable Direct Root SSH Login & Enforce Key-Based Authentication:** Configure drop-in overrides in `/etc/ssh/sshd_config.d/99-hyperion-hardening.conf` (avoiding direct edits to `/etc/ssh/sshd_config` to prevent package upgrade conflicts):
  ```ini
  PermitRootLogin no
  PubkeyAuthentication yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  PermitEmptyPasswords no
  MaxAuthTries 3
  ```
* **Enforce Least-Privilege `sudo`:** Prohibit shared accounts; require individual user accounts with explicit `sudo` rules in `/etc/sudoers.d/` and require re-authentication (`timestamp_timeout=5`).
* **Lock Inactive Accounts:** Automatically lock inactive user accounts after 30 days:
  ```bash
  useradd -D -f 30
  ```
* **Password Complexity Enforcement:** Enforce strong password policies via `pam_pwquality` (`/etc/security/pwquality.conf`):
  ```ini
  minlen = 14
  dcredit = -1
  ucredit = -1
  ocredit = -1
  lcredit = -1
  ```

---

### 5. Cryptographic Controls (`A.8.24`)
* **Modern OpenSSH Algorithms:** Restrict SSH to strong, modern key exchange, cipher, and MAC algorithms in `/etc/ssh/sshd_config.d/99-hyperion-hardening.conf`:
  ```ini
  KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
  MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
  ```
* **Data at Rest Encryption:** Encrypt root volumes, data partitions, and swap using **LUKS2** (`cryptsetup`) or cloud provider KMS-backed volume encryption.
* **Data in Transit Encryption (TLS 1.2 / 1.3 Only):** Strictly disable legacy SSLv2, SSLv3, TLS 1.0, and TLS 1.1 across all web servers, proxies, and internal APIs. Enforce **TLS 1.2 and TLS 1.3** exclusively.
* **Secrets & Key Management:** Never store private keys, TLS certificates, or API secrets in plaintext repositories; manage via HashiCorp Vault, AWS/GCP KMS, or encrypted secret stores with strict `0600` file permissions.

---

### 6. Secure Configuration & Kernel Hardening (`A.8.9`)
* **Minimize Attack Surface:** Audit listening sockets (`ss -tulnp`) and disable/remove all unnecessary daemons (e.g., `avahi-daemon`, `cups`, `rpcbind`, `telnet`). Enforce a default-deny host firewall (`ufw`, `nftables`, or `firewalld`).
* **Restrictive File Permissions & `umask`:** Set default `umask 027` in `/etc/profile` and `/etc/login.defs`. Ensure critical files maintain strict ownership and modes (`/etc/passwd` `0644`, `/etc/shadow` `0640` or `0000`, `/etc/ssh/sshd_config` `0600`).
* **Partition Mount Hardening (`/etc/fstab`):**
  * `/tmp`, `/var/tmp`, and `/dev/shm`: Mount with `defaults,noexec,nosuid,nodev`
  * `/var`: Mount with `defaults,nosuid,nodev` *(omit `noexec` to preserve package managers and container runtimes)*
  * `/home`: Mount with `defaults,nosuid,nodev`
* **Kernel Network & Memory Hardening (`/etc/sysctl.d/99-hyperion-hardening.conf`):**
  ```ini
  kernel.randomize_va_space = 2
  kernel.dmesg_restrict = 1
  kernel.kptr_restrict = 2
  kernel.yama.ptrace_scope = 1
  net.ipv4.tcp_syncookies = 1
  net.ipv4.ip_forward = 0
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.send_redirects = 0
  net.ipv4.conf.all.rp_filter = 1
  ```
* **Mandatory Access Control (MAC):** Keep **SELinux** in `enforcing` mode on RHEL/Rocky/AlmaLinux/Fedora (`getenforce`), or **AppArmor** enabled and enforcing profiles on Debian/Ubuntu (`aa-status`).

---

### 7. Logging, Monitoring & Clock Synchronization (`A.8.15`, `A.8.16`, `A.8.17`)
* **Persistent Systemd Journal (`A.8.15`):** Configure `Storage=persistent` in `/etc/systemd/journald.conf` so authentication and service logs survive reboots (`journalctl -u ssh`). Where text logs or SIEM forwarding are required, configure `rsyslog` or `Vector` over TLS.
* **Kernel-Level Audit Trail (`A.8.15`, `A.8.16`):** Deploy **Hyperion Trace** eBPF probes to stream tamper-evident records of privileged executions (`execve`), `sudo` escalations, and sensitive file writes (`/etc/`, `/root/.ssh/`) to Hyperion State—or maintain hardened `auditd` rules (`/etc/audit/rules.d/`) as a local fallback.
* **Alerting on Anomalous Access (`A.8.16`):** Trigger real-time alerts on repeated failed SSH logins, unauthorized `sudo` attempts, new user/SSH key additions, and out-of-band configuration changes.
* **Mandatory NTP Time Synchronization (`A.8.17`):** Enable `chrony` or `systemd-timesyncd` (`timedatectl status`) synced to authenticated stratum 1/2 NTP servers to guarantee accurate forensic log correlation and TLS certificate validation.

---

### 8. Malware & Runtime Integrity Protection (`A.8.7`)
* **File Integrity Monitoring (FIM):** Continuously monitor cryptographic hashes and write syscalls across `/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, and `/boot` using Hyperion Trace (or AIDE) to detect unauthorized binary replacement or backdoors.
* **Runtime Behavioral Detection:** Monitor unexpected child processes spawned by web/database services (e.g., `nginx` or `postgres` spawning `/bin/sh` or `curl`) via eBPF `execve` tracing.
* **Targeted Antivirus Scanning:** Deploy `ClamAV` (`freshclam` + `clamd`) specifically on servers handling untrusted external file uploads or mail relay traffic.

---

### 9. System Update & Vulnerability Management (`A.8.8`)
* **Debian / Ubuntu Automated Security Patching:** Enable `unattended-upgrades`:
  ```bash
  apt-get install -y unattended-upgrades apt-listchanges
  dpkg-reconfigure -plow unattended-upgrades
  ```
* **RHEL 8/9/10 / Rocky / AlmaLinux / Fedora Automated Patching:** Configure **`dnf-automatic`** (replacing deprecated `yum-cron`):
  ```bash
  dnf install -y dnf-automatic
  sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
  systemctl enable --now dnf-automatic-install.timer
  ```
* **Patch & Kernel Reboot Verification:** Audit package update logs (`/var/log/unattended-upgrades/` or `dnf history`) and verify pending kernel reboots (`needs-restarting -r` on RHEL or `/var/run/reboot-required` on Debian/Ubuntu).

---

### 10. Continuous Review, Deviation Tracking & Audit (`A.5.36`)
* **Continuous Automated Posture Auditing:** Run daily automated compliance scans via **Hyperion Trace** to verify all controls in Sections 4–9, supplemented by quarterly deep-dive benchmark runs using **OpenSCAP** (`oscap`) or **Lynis**.
* **Deviation & Exception Governance:** Any server requiring a temporary deviation from this baseline (e.g., enabling IP forwarding on a VPN gateway) must be explicitly tagged as an approved exception in Hyperion State with a documented business justification, compensating control, and expiration date.
* **Auditor Evidence Export:** Export signed JSON/CSV/PDF compliance reports directly from Hyperion State prior to internal or external ISO/IEC 27001 surveillance audits.
