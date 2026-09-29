#!/usr/bin/env bash
# File: /opt/scripts/remediate_mint01.sh

set -euo pipefail

echo "[+] Executing automated hardening..."

# 1. PAM Account Lockout
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    echo "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900" >> /etc/pam.d/common-auth
fi

# 2. Audit Daemon
if ! command -v auditd &> /dev/null; then
    apt-get update -qq && apt-get install -y -qq auditd
fi
systemctl enable --now auditd

# 3. Max Password Expiration
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs

# 4. Disable Print Daemon
if systemctl is-active --quiet cups 2>/dev/null; then
    systemctl disable --now cups
fi

# 5. Trigger Wazuh Rescan
systemctl restart wazuh-agent
echo "[✓] Endpoint hardening complete."
