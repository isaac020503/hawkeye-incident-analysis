# HawkEye Incident Analysis

SOC investigation of a HawkEye Keylogger (Reborn v9) infection, based on the CyberDefenders **HawkEye** network-forensics lab.

**Live page:** https://isaac020503.github.io/hawkeye-incident-analysis/
**Full report:** [Incident Report HawkEye Stealer Infection.pdf](Incident%20Report%20HawkEye%20Stealer%20Infection.pdf)

## Summary

A workstation (`BEIJING-5CD1-PC`, 10.4.10.132) in the `pizzajukebox.com` domain downloaded and ran a HawkEye Keylogger payload on 10 April 2019, then emailed the user's saved browser and Outlook credentials to an attacker-controlled mailbox. Severity: **High**.

Scenario from the lab: an accountant opened an invoice email with a download link, and suspicious traffic followed. The capture shows the download, the malware's check-ins and the data theft. It does not show the original phishing email.

## What's in this repo

| File | What it is |
|------|------------|
| `Incident Report HawkEye Stealer Infection.pdf` | Full incident report: timeline, indicators, exfiltration analysis, ATT&CK mapping, recommendations |
| `detections.md` | Detection rules derived from the incident, with a Sigma-style example |
| `tools/pcap_summary.py` | Python script that summarises a `.pcap` and flags suspicious behaviour |
| `index.html` | The live summary page (GitHub Pages) |

## Using the script

Needs only Python 3, no extra packages.

```bash
python3 tools/pcap_summary.py stealer.pcap
```

It prints the packet count, busiest connections, DNS queries and HTTP requests, and raises an alert for:

- a Windows executable downloaded over plain HTTP
- a workstation connecting to an external SMTP server (ports 25, 465, 587)

The capture file is not included here. Download it from the CyberDefenders HawkEye lab.

## Key findings

- Payload `tkraw_Protected99.exe` fetched from `proforma-invoices.com` (217.182.138.150) over HTTP.
- Stolen data sent by SMTP (port 587) to a mailbox on `macwinlogistics.in` (23.229.162.69), seven times at about 10-minute intervals.
- Email subject names the malware: "HawkEye Keylogger - Reborn v9 - Passwords Logs".
- SHA-256 of the payload: `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11`

## Tools used

Wireshark, Python

## Note

Educational analysis of a public training lab. The data belongs to a fictional victim, and passwords seen in the capture are deliberately not reproduced.
