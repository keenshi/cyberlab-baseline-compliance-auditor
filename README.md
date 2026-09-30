# Enterprise Security Baseline Audit & Automated Remediation Pipeline

An end-to-end ICT Risk Management and Baseline Compliance workflow executed within the **CyberLab** environment. This project demonstrates automated vulnerability ingestion via **Wazuh SCA (Security Configuration Assessment)**, risk scoring using a standard $5 \times 5$ Risk Matrix, structured Risk Register documentation, executive presentation reporting, and shell-based security remediation.

---

## 📌 Executive Summary

Modern enterprise IT/OT environments require continuous baseline monitoring and rapid remediation to adhere to standards such as **CIS Benchmarks**, **ISO/IEC 27001**, and **NIST SP 800-53**.

In this project, an endpoint node (`mint01`) monitored by a dual-homed **Wazuh SIEM Manager** underwent a Security Configuration Assessment (SCA). Initial findings revealed an acceptable baseline compliance score of **42.86%** across evaluated checks (3 Passed, 4 Failed). Findings were extracted, categorized, scored based on Impact vs. Likelihood ($L \times I$), and mapped to SLA-driven mitigation targets. Following shell-based automated remediation, the system achieved an **85.71% compliance score (6 Passed, 1 Failed)**, representing a **+42.85% posture improvement**.

---

## 📊 Remediation Metrics & Key Performance Indicators (KPIs)

<img width="1662" height="220" alt="Risk Assessment Summary Dashboard" src="https://github.com/user-attachments/assets/343f273c-f757-4413-9dfe-8ce2a1212a21" />

### After Remidiation
<img width="1912" height="910" alt="image" src="https://github.com/user-attachments/assets/df2847c0-ce8a-452f-9b38-95b65acdb502" />


### Compliance Delta (Initial vs. Phase 1 Remediation)

| Compliance Metric | Initial SCA Audit | Phase 1 Remediation Audit | Metric Delta |
| :--- | :---: | :---: | :---: |
| **Total Evaluated CIS Controls** | 7 | 7 | 0 |
| **Passed Checks** | 3 | 6 | **+3** |
| **Failed Checks** | 4 | 1 | **-3** |
| **Not Applicable Checks** | 16 | 16 | 0 |
| **Overall Compliance Score (%)** | **42.86%** | **85.71%** *(Wazuh Dashboard: 85%)* | **+42.85%** |

---

## 🛡️ Risk Assessment & Remediation Log

Inherent Risk Scores are calculated using the enterprise formula:

$$\text{Inherent Risk Score} = \text{Impact (1–5)} \times \text{Likelihood (1–5)}$$

| Risk ID | Vulnerability / Control Finding | Threat Description & Framework Mapping | Impact | Likelihood | Risk Score | Severity | Remediation SLA | Applied Remediation | Final Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- | :---: |
| **RISK-MINT-01** | Missing PAM Account Lockout Policy | System lacks lockout mechanisms after repeated failed login attempts; vulnerable to brute-force attacks (*NIST SP 800-53 IA-5*). | 4 | 4 | **16** | **High** | 14 Days | Appended `pam_faillock` rule (`deny=5`, `unlock_time=900`) to `/etc/pam.d/common-auth`. | **Mitigated** |
| **RISK-MINT-02** | Disabled System Audit Daemon (`auditd`) | System logging daemon is inactive; severely limits forensic tracing and event visibility (*CIS CSC 6.2/6.3*). | 4 | 4 | **16** | **High** | 14 Days | Installed and enabled service via `apt install auditd` and `systemctl enable --now auditd`. | **Mitigated** |
| **RISK-MINT-03** | Unbounded Password Expiration Period | `PASS_MAX_DAYS` parameter exceeds 365 days; increases exposure window for compromised credentials (*CIS CSC 4.4*). | 3 | 3 | **9** | **Medium** | 30 Days | Modified `/etc/login.defs` setting `PASS_MAX_DAYS 365`. | **Mitigated** |
| **RISK-MINT-04** | Active Unnecessary Print Service (`cups`) | Print service enabled on non-printing system; expands unneeded network attack surface (*CIS CSC 9.1/9.2*). | 2 | 3 | **6** | **Medium** | 30 Days | Stopped and disabled daemon via `systemctl disable --now cups`. | **Mitigated** |
| **RISK-MINT-05** | SSH Configuration Hardening Finding | SSH service configuration requires hardening per CIS benchmark standards. | 3 | 3 | **9** | **Medium** | 30 Days | *Pending Final SSH Parameter Tuning* | **In Progress** |

---

## ☑️ Risk Matrix: Impact vs. Likelihood

Risks are prioritized and mapped using a standard $5 \times 5$ Risk Assessment Matrix to determine operational SLA enforcement:

<img width="871" height="435" alt="Impact vs Likelihood Risk Matrix" src="https://github.com/user-attachments/assets/313af4b4-b2d0-4e2a-babd-468e734b37ff" />

### Severity & SLA Action Guide

| Severity Level | Risk Score Range | Color Code | Remediation SLA | Operational Action Required |
| :--- | :---: | :--- | :---: | :--- |
| **Critical** | **20 – 25** | Dark Red | **7 Days** | Emergency patch deployment; direct escalation to CISO and system owners. |
| **High** | **12 – 19** | Light Red | **14 Days** | Priority remediation within the current operational sprint. |
| **Medium** | **6 – 11** | Yellow | **30 Days** | Scheduled remediation during the standard monthly maintenance window. |
| **Low** | **1 – 5** | Green | **60–90 Days** | Risk accepted or remediated during routine system updates. |

---

## 🔧 Remediation Script (`scripts/remediate_mint01.sh`)

To enforce consistency and eliminate manual errors, remediation was automated using the following shell script:

```bash
#!/usr/bin/env bash
# ==============================================================================
# Script Name:   remediate_mint01.sh
# Description:   Automated CIS Security Baseline Remediation Script for mint01
# Target System: Linux / Ubuntu / Debian-based systems
# ==============================================================================

set -euo pipefail

echo "=================================================="
echo "[+] Starting Security Baseline Remediation Pipeline"
echo "=================================================="

# 1. Remediate RISK-MINT-01: Configure PAM Account Lockout
echo "[+] [1/5] Enforcing PAM Account Lockout Policy..."
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    echo "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth
    echo "    -> PAM account lockout rule added successfully."
else
    echo "    -> PAM account lockout rule already exists."
fi

# 2. Remediate RISK-MINT-02: Install and Enable Audit Daemon
echo "[+] [2/5] Ensuring auditd service is installed and active..."
if ! command -v auditd &> /dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq auditd
fi
sudo systemctl enable --now auditd
echo "    -> auditd service enabled and running."

# 3. Remediate RISK-MINT-03: Set Maximum Password Expiration (365 Days)
echo "[+] [3/5] Setting PASS_MAX_DAYS to 365 in /etc/login.defs..."
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
echo "    -> Password max age updated."

# 4. Remediate RISK-MINT-04: Disable Unnecessary Print Daemon (CUPS)
echo "[+] [4/5] Disabling CUPS service..."
if systemctl is-active --quiet cups; then
    sudo systemctl disable --now cups
    echo "    -> CUPS service stopped and disabled."
else
    echo "    -> CUPS service already disabled."
fi

# 5. Force Rescan in Wazuh Agent
echo "[+] [5/5] Restarting Wazuh Agent to trigger immediate SCA audit rescan..."
sudo systemctl restart wazuh-agent

echo "=================================================="
echo "[✓] Phase 1 Remediation Complete. Compliance score verified at 85.71%."
echo "=================================================="
