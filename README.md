# hawkeye-incident-analysis
SOC

A workstation (BEIJING-5CD1-PC, 10.4.10.132) in the pizzajukebox.com domain downloaded and ran a HawkEye Keylogger – Reborn v9 payload on 10 April 2019, then emailed the user's saved browser and Outlook credentials to an attacker-controlled mailbox. Severity: High. Credentials for the user roman.mcguire, including a bank site, a personal AOL account and the corporate mail account, must be treated as compromised.
The scenario given with the lab: an accountant opened an invoice email with a download link, and suspicious traffic followed. The capture shows the download, the malware's check-ins and the data theft. It does not show the original phishing email.
Tools used: Wireshar,Python
