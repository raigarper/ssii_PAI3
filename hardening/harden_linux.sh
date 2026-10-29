#!/usr/bin/env bash
# ==============================================================================
# PAI-3 VULNAWEB - Endpoint Hardening Automation Script
# Target: Debian / Ubuntu Linux Workstations (PDI / PTGAS)
# Objective: Achieve Lynis Hardening Index >= 70 (CIS Benchmark alignment)
# ==============================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[ERROR] This script must be run as root (use sudo)." >&2
   exit 1
fi

echo "=========================================================="
echo " Starting Endpoint Security Hardening (Target Index >= 70)"
echo "=========================================================="

BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
echo "[+] Created configuration backup directory at $BACKUP_DIR"

# ------------------------------------------------------------------------------
# 1. Update Packages & Install Security Utilities
# ------------------------------------------------------------------------------
echo "[*] Step 1: Installing security and audit management packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-show-versions \
    debsums \
    unattended-upgrades \
    libpam-pwquality \
    ufw \
    fail2ban \
    auditd \
    audispd-plugins \
    rkhunter \
    acct

# Enable automatic security updates
dpkg-reconfigure -f noninteractive unattended-upgrades

# ------------------------------------------------------------------------------
# 2. Kernel & Network Hardening (sysctl)
# ------------------------------------------------------------------------------
echo "[*] Step 2: Applying kernel and network sysctl hardening..."
SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"

cat << 'EOF' > "$SYSCTL_CONF"
# Virtual memory and memory protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
kernel.core_uses_pid = 1

# Network protocol protection (IPv4 / IPv6)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
EOF

sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

# ------------------------------------------------------------------------------
# 3. Disable Unused Filesystems & Storage Drivers (STRG-1840, STRG-1846)
# ------------------------------------------------------------------------------
echo "[*] Step 3: Disabling legacy and unused storage/filesystem kernel modules..."
MODPROBE_CONF="/etc/modprobe.d/security-hardening.conf"

cat << 'EOF' > "$MODPROBE_CONF"
# Disable firewire and uncommon network protocols
install firewire-core /bin/true
install firewire_core /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Disable uncommon / legacy filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# ------------------------------------------------------------------------------
# 4. Authentication, PAM & Password Quality (AUTH-9262, AUTH-9282, AUTH-9286)
# ------------------------------------------------------------------------------
echo "[*] Step 4: Configuring password policies and PAM quality checks..."
cp /etc/login.defs "$BACKUP_DIR/login.defs.bak"

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs

# Stricter umask in /etc/profile and /etc/init.d/rc (AUTH-9328)
if ! grep -q "umask 027" /etc/profile; then
    echo "umask 027" >> /etc/profile
fi

# Configure PAM password quality rules
PWQUALITY_CONF="/etc/security/pwquality.conf"
cat << 'EOF' > "$PWQUALITY_CONF"
# Password quality enforcement
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
usercheck = 1
enforce_for_root
EOF

# ------------------------------------------------------------------------------
# 5. Core Dumps & Resource Limits
# ------------------------------------------------------------------------------
echo "[*] Step 5: Disabling core dumps for all users..."
LIMITS_CONF="/etc/security/limits.d/99-disable-coredump.conf"
cat << 'EOF' > "$LIMITS_CONF"
* hard core 0
* soft core 0
EOF

# ------------------------------------------------------------------------------
# 6. Legal Login Banners (BANN-7126, BANN-7130)
# ------------------------------------------------------------------------------
echo "[*] Step 6: Setting authoritative legal warning banners..."
BANNER_TEXT="************************************************************************
* AVISO LEGAL: ACCESO RESTRINGIDO - UNIVERSIDAD PUBLICA U-SECURE       *
* El acceso a este sistema esta reservado exclusivamente a personal     *
* autorizado (PDI/PTGAS). Todas las actividades son monitorizadas y    *
* auditadas conforme al Esquema Nacional de Seguridad (ENS).           *
* El uso no autorizado sera perseguido legalmente.                     *
************************************************************************"

echo "$BANNER_TEXT" > /etc/issue
echo "$BANNER_TEXT" > /etc/issue.net
echo "$BANNER_TEXT" > /etc/motd

# ------------------------------------------------------------------------------
# 7. SSH Daemon Hardening (SSH-7408)
# ------------------------------------------------------------------------------
echo "[*] Step 7: Hardening OpenSSH Server configuration..."
if [ -d /etc/ssh ]; then
    SSHD_HARDENING="/etc/ssh/sshd_config.d/99-hardening.conf"
    mkdir -p /etc/ssh/sshd_config.d
    cat << 'EOF' > "$SSHD_HARDENING"
# Corporate SSH hardening profile
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 60
X11Forwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
Banner /etc/issue.net
EOF
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# 8. Host-based Firewall Configuration (UFW) (FIRE-4590)
# ------------------------------------------------------------------------------
echo "[*] Step 8: Configuring local firewall (UFW)..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH restricted administration'
ufw --force enable

# ------------------------------------------------------------------------------
# 9. Audit & Intrusion Detection Daemons
# ------------------------------------------------------------------------------
echo "[*] Step 9: Starting audit and defensive services..."
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
systemctl enable fail2ban 2>/dev/null || true
systemctl start fail2ban 2>/dev/null || true

# ------------------------------------------------------------------------------
# 10. File Permissions Hardening
# ------------------------------------------------------------------------------
echo "[*] Step 10: Setting strict file permissions on critical system paths..."
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true
chmod 640 /etc/shadow 2>/dev/null || true
chmod 644 /etc/passwd /etc/group 2>/dev/null || true

echo "=========================================================="
echo " Hardening complete. Please run a Lynis audit to verify."
echo " Backup stored at: $BACKUP_DIR"
echo "=========================================================="
