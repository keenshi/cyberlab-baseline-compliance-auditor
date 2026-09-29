# cyberlab-baseline-compliance-auditor


# Enterprise ICT Security Baseline Audit & Automated Remediation Pipeline

## Executive Summary
This project demonstrates an end-to-end ICT Risk Management & Compliance lifecycle performed on an enterprise endpoint in the **CyberLab** environment. Using **Wazuh SCA (Security Configuration Assessment)** aligned with **CIS Benchmarks**, baseline failures were ingested, evaluated on a $5 \times 5$ Risk Matrix, documented in a structured Risk Register, and systematically remediated.

---

## 📊 Pre vs. Post Remediation Metrics

| Metric | Initial SCA Audit | Post-Remediation Audit | Delta |
| :--- | :---: | :---: | :---: |
| **Evaluated CIS Controls** | 7 | 7 | -- |
| **Passed Checks** | 3 | 7 | **+4** |
| **Failed Checks** | 4 | 0 | **-4** |
| **Overall Compliance Score** | **42.86%** | **100.00%** | **+57.14%** |

---

## 🛡️ Evaluated Risks & Remediation Log

| Risk ID | Vulnerability / Finding | Inherent Risk | Severity | Initial Status | Remediation Applied | Final Status |
| :--- | :--- | :---: | :---: | :---: | :--- | :---: |
| **RISK-MINT-01** | Missing PAM account lockout configuration | $4 \times 4 = 16$ | High | Open | Configured `pam_faillock` (deny=5, unlock=900s) | **Mitigated** |
| **RISK-MINT-02** | Disabled `auditd` logging daemon | $4 \times 4 = 16$ | High | Open | Enabled service (`systemctl enable --now auditd`) | **Mitigated** |
| **RISK-MINT-03** | Password expiration exceeding 365 days | $3 \times 3 = 9$ | Medium | Open | Updated `/etc/login.defs` (`PASS_MAX_DAYS 365`) | **Mitigated** |
| **RISK-MINT-04** | Unnecessary print service (`cups`) running | $2 \times 3 = 6$ | Medium | Open | Disabled service (`systemctl disable --now cups`) | **Mitigated** |

---

## 📑 Repository Content & Deliverables
* `docs/CyberLab-Risk-Assessment.csv` — Full Risk Register template with formulas, impact/likelihood scoring, and dynamic SLAs.
* `docs/Executive_Presentation_Deck.pdf` — Executive-level briefing deck summarizing posture, top risks, and mitigation roadmaps.
* `scripts/remediate_mint01.sh` — Bash automation script applied to remediate baseline findings.
