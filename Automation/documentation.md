# Automation Documentation

## 1. Executive Overview
This document outlines the operational methodology, architectural workflow, and technical execution of the **CyberLab Baseline Compliance & Risk Remediation Pipeline**. 

Using **Wazuh SCA (Security Configuration Assessment)** aligned with **CIS Benchmarks**, baseline compliance failures were ingested from an audited Linux endpoint (`mint01`), evaluated on a standard $5 \times 5$ Risk Matrix, tracked in a structured Risk Register, and systematically remediated using automated shell scripts.

---

## 2. End-to-End Workflow Architecture

```text
┌────────────────────────────────┐
│   1. Endpoint Audit (Wazuh)    │  <-- Evaluates node against CIS Benchmarks
└───────────────┬────────────────┘
                │ Raw Scan CSV
                ▼
┌────────────────────────────────┐
│ 2. Data Ingestion & Scoring    │  <-- Calculates Impact x Likelihood scores
└───────────────┬────────────────┘
                │ Structured Risk Data
                ▼
┌────────────────────────────────┐
│ 3. Risk Register & SLAs        │  <-- Maps findings to 14/30/60-day SLAs
└───────────────┬────────────────┘
                │ Actionable Fixes
                ▼
┌────────────────────────────────┐
│ 4. Automated OS Hardening      │  <-- Runs `remediate_mint01.sh`
└───────────────┬────────────────┘
                │ Agent Rescan
                ▼
┌────────────────────────────────┐
│ 5. 100% Verified Compliance    │  <-- Rescan confirms 0 failed checks
└────────────────────────────────┘
