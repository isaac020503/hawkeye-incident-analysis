# Detection ideas from the HawkEye incident

Each rule is written as plain logic so it can be translated to any SIEM (Splunk, Wazuh, Elastic, Sentinel).
Test data for them: the stealer pcap from the CyberDefenders HawkEye lab (not included in this repo).

| # | Detection | Logic | Why it works | ATT&CK |
|---|-----------|-------|--------------|--------|
| 1 | Workstation sends mail directly | Source is not a mail server AND destination port in (25, 465, 587) AND destination is external | Only mail servers should talk SMTP to the internet. HawkEye sent its stolen data this way. | T1048.003 |
| 2 | Executable downloaded over HTTP | HTTP response with `Content-Type: application/x-msdownload` or a body starting `MZ` | Real software is rarely fetched as a plain `.exe` over unencrypted HTTP. | T1105 |
| 3 | Repeated public-IP lookups | Same host requests `bot.whatismyipaddress.com` (or similar IP-check sites) at a regular interval | Malware checks its public IP on a timer. In this capture it repeated every ~10 minutes. | T1016 |
| 4 | Known malware subject line | Outbound mail subject contains `HawkEye Keylogger` | HawkEye puts its name and version in the subject of exfiltration emails. | T1555.003 |
| 5 | Known indicators | Match payload hashes, domains and IPs from the report | Fast and precise for this exact sample, but easy for attackers to change. | n/a |

## Sigma-style example (rule 1)

```yaml
title: Workstation sending SMTP to the internet
status: experimental
logsource:
  category: firewall
detection:
  selection:
    dst_port:
      - 25
      - 465
      - 587
  filter_mailservers:
    src_ip:
      - 10.4.10.25   # replace with your real mail servers
  condition: selection and not filter_mailservers
falsepositives:
  - Users with a legitimate mail client configured to reach an external provider
level: high
```

## Indicators from this incident

| Type | Value |
|------|-------|
| Domain | `proforma-invoices.com` |
| Domain | `macwinlogistics.in` |
| IP | `217.182.138.150` |
| IP | `23.229.162.69` |
| SHA-256 | `62099532750dad1054b127689680c38590033fa0bdfa4fb40c7b4dcb2607fb11` |
