# Enable and start auditd logging daemon (RISK-MINT-02)
sudo systemctl enable --now auditd

# Disable unnecessary CUPS print service (RISK-MINT-04)
sudo systemctl disable --now cups

# Configure max password age to 365 days in /etc/login.defs (RISK-MINT-03)
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs

# Configure PAM account lockout in /etc/pam.d/common-auth (RISK-MINT-01)
# Append pam_faillock / pam_tally2 rule
echo "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900" | sudo tee -a /etc/pam.d/common-auth

# Restart Wazuh Agent to trigger an immediate rescannable baseline audit
sudo systemctl restart wazuh-agent
