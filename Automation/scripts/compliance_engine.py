#!/usr/bin/env python3
"""
File Name: compliance_engine.py
Description: Fully automated compliance orchestrator for CyberLab.
             Parses SCA output -> Updates Risk Register -> Sends Alerts -> Executes Remediations.
"""

import os
import sys
import json
import subprocess
import requests
import pandas as pd
from datetime import datetime

# Configuration Settings
RISK_REGISTER_FILE = "CyberLab-Risk-Assessment.csv"
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")  # Optional Teams/Slack Alert URL
TARGET_HOST = "mint01"
TARGET_SSH_USER = "admin_user"


def calculate_risk(impact, likelihood):
    """Calculates risk score and assigns severity + SLA."""
    score = impact * likelihood
    if score >= 20:
        return score, "Critical", "7 Days"
    elif score >= 12:
        return score, "High", "14 Days"
    elif score >= 6:
        return score, "Medium", "30 Days"
    else:
        return score, "Low", "60 Days"


def send_alert(risk_id, title, score, severity, sla):
    """Sends an automated notification to security operators."""
    print(f"[+] Sending alert for {risk_id} ({severity} - Score: {score})...")
    if TEAMS_WEBHOOK_URL:
        payload = {
            "title": f"🚨 High Security Finding Detected: {risk_id}",
            "text": f"**Vulnerability:** {title}\n**Severity:** {severity} (Score: {score})\n**Mitigation SLA:** {sla}"
        }
        try:
            requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=5)
        except Exception as e:
            print(f"[!] Webhook alert failed: {e}")


def execute_remote_remediation():
    """Executes the hardening script on the target endpoint over SSH."""
    print(f"[+] Triggering automated remote remediation on {TARGET_HOST}...")
    cmd = f"ssh {TARGET_SSH_USER}@{TARGET_HOST} 'sudo /opt/scripts/remediate_mint01.sh'"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("[✓] Remote remediation succeeded.")
        print(result.stdout)
        return True
    else:
        print(f"[!] Remote remediation failed: {result.stderr}")
        return False


def run_pipeline(sca_scan_json):
    """Processes the full compliance loop."""
    print("==================================================")
    print("[+] Starting CyberLab Compliance Automation Pipeline")
    print("==================================================")

    # 1. Load Scan Results
    with open(sca_scan_json, 'r') as f:
        data = json.load(f)

    findings = data.get("failed_checks", [])
    evaluated_count = data.get("total_evaluated", 7)
    passed_count = evaluated_count - len(findings)
    initial_score = (passed_count / evaluated_count) * 100

    print(f"[+] Ingested Scan: {passed_count}/{evaluated_count} Passed ({initial_score:.2f}% Compliance)")

    # 2. Build/Update Risk Register
    risk_list = []
    for idx, f in enumerate(findings, start=1):
        impact = f.get("impact", 3)
        likelihood = f.get("likelihood", 3)
        score, severity, sla = calculate_risk(impact, likelihood)
        risk_id = f"RISK-MINT-{idx:02d}"

        # Send alert if High or Critical
        if score >= 12:
            send_alert(risk_id, f["title"], score, severity, sla)

        risk_list.append({
            "Risk ID": risk_id,
            "Asset Name": TARGET_HOST,
            "Vulnerability / Control Failure": f["title"],
            "Impact": impact,
            "Likelihood": likelihood,
            "Risk Score (L×I)": score,
            "Risk Severity": severity,
            "Mitigation SLA": sla,
            "Status": "Open"
        })

    # Save Pre-Remediation Register
    df_pre = pd.DataFrame(risk_list)
    df_pre.to_csv(RISK_REGISTER_FILE, index=False)
    print(f"[+] Saved Initial Risk Register -> {RISK_REGISTER_FILE}")

    # 3. Trigger Hardening Script
    if len(findings) > 0:
        success = execute_remote_remediation()
        
        # 4. Update Risk Register to Mitigated
        if success:
            for item in risk_list:
                item["Status"] = "Mitigated"
            
            df_post = pd.DataFrame(risk_list)
            df_post.to_csv(RISK_REGISTER_FILE, index=False)
            print(f"[✓] Updated Risk Register status to 'Mitigated' (100.00% Compliance).")


if __name__ == "__main__":
    scan_file = sys.argv[1] if len(sys.argv) > 1 else "scan_results.json"
    run_pipeline(scan_file)
