# ThreatScope — Cyber Threat Intelligence Platform

**Live Demo:** https://threatscope-intelligence-platform-ayyocenhf7b27sanjrox4u.streamlit.app

**Built by:** Priyanshi Dhokiya | M.S. Cybersecurity, Saint Louis University

---

## Overview

ThreatScope is a real-time threat intelligence platform that analyzes suspicious IP addresses by querying multiple threat databases simultaneously. Built to simulate enterprise SOC analyst workflows for IOC enrichment and threat investigation.

## Features

- Real-time IP analysis using VirusTotal and AbuseIPDB APIs
- 70+ security vendor votes via VirusTotal
- Abuse confidence scoring with ISP and geolocation data
- Automatic MITRE ATT&CK technique mapping
- Risk scoring — Critical, High, Low
- Interactive charts — vendor analysis pie chart and risk gauge
- Downloadable incident reports
- Bulk IP analysis support

## Tech Stack

- Python 3.11
- Streamlit
- Plotly
- VirusTotal API v3
- AbuseIPDB API v2
- MITRE ATT&CK Framework

## MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|---|---|---|
| Proxy: Multi-hop Proxy | T1090.003 | Defense Evasion |
| Brute Force: Password Guessing | T1110.001 | Credential Access |
| Active Scanning | T1595 | Reconnaissance |
| Application Layer Protocol | T1071 | Command and Control |

## Sample Analysis

Analyzed IP: 185.220.101.45
- Country: Germany
- ISP: Network for Tor-Exit traffic
- VirusTotal: 15/64 vendors flagged malicious
- AbuseIPDB: 100/100 abuse score — 108 reports
- Risk Level: CRITICAL
- MITRE Techniques: 3 mapped
- Action: BLOCK IMMEDIATELY

## Author

Priyanshi Dhokiya
- LinkedIn: linkedin.com/in/priyanshi-dhokiya
- GitHub: github.com/priyanshi-dh2
