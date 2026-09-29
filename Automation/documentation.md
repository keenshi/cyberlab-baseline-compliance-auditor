# Automation Documentation

## 1. Executive Overview
This document outlines the operational methodology, architectural workflow, and technical execution of the **CyberLab Baseline Compliance & Risk Remediation Pipeline**. 

Using **Wazuh SCA (Security Configuration Assessment)** aligned with **CIS Benchmarks**, baseline compliance failures were ingested from an audited Linux endpoint (`mint01`), evaluated on a standard $5 \times 5$ Risk Matrix, tracked in a structured Risk Register, and systematically remediated using automated shell scripts.

---

## 2. End-to-End Workflow Architecture

```text
┌──────────────────────────┐
│ Wazuh SIEM Manager (SCA) │
└────────────┬─────────────┘
             │ 1. Triggers Webhook on "SCA Audit Failed" Event
             ▼
┌──────────────────────────┐
│ Python Orchestrator API  │
│  (`compliance_engine.py`)│ ──> 2. Parses Wazuh Event Payload
└────────────┬─────────────┘     3. Calculates $L \times I$ Risk Score & SLA
             │                   4. Updates CSV / Excel / SharePoint Register
             │                   5. Sends Teams/Email Alert (via Webhook)
             │
             │ 6. Executes Remotely via SSH
             ▼
┌──────────────────────────┐
│   Target Endpoint Node   │
│     (`remediate.sh`)     │ ──> 7. Hardens OS Settings (PAM, auditd, CUPS)
└────────────┬─────────────┘     8. Restarts Wazuh Agent
             │
             ▼
┌──────────────────────────┐
│ Rescan & Auto-Closure    │ ──> 9. Python API sets Risk Status to "Mitigated"
└──────────────────────────┘
