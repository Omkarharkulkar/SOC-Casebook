# SOC Casebook
### SOC L1 Investigation & Incident Response Portfolio

SOC Casebook is a hands-on cybersecurity portfolio project focused on security alert triage, investigation, evidence analysis, and incident documentation.

The project simulates selected responsibilities of a Level 1 Security Operations Center (SOC) analyst using real-world security datasets and controlled lab-generated events.

## Project Objectives

- Investigate suspicious security events from different data sources.
- Analyze Linux authentication and system activity.
- Examine Windows event logs and process activity.
- Investigate phishing indicators and suspicious network traffic.
- Practice SIEM alert investigation.
- Document findings, assess severity, and recommend response actions.
- Develop practical SOC investigation playbooks.

## Investigation Cases

| Case ID | Investigation | Status |
|---|---|---|
| CASE-001 | SSH Brute-Force Investigation | Planned |
| CASE-002 | Suspicious Windows Process Execution | Planned |
| CASE-003 | Legitimate Administrative Activity | Planned |
| CASE-004 | Phishing Email Investigation | Planned |
| CASE-005 | Suspicious DNS / Network Communication | Planned |
| CASE-006 | SIEM Alert Investigation | Planned |
| CASE-007 | Linux Privilege and Account Activity | Planned |
| CASE-008 | Legitimate Linux Administrative Activity | Planned |

Case verdicts will be based on collected evidence rather than predetermined assumptions.

## Project Components

### 1. Security Investigations
Eight documented investigations covering Linux, Windows, phishing, network traffic, and SIEM alerts.

### 2. MiniSOC
A lightweight Python-based Linux log collection and analysis module using structured storage and basic detection logic.

### 3. IOC Enrichment
A supporting utility for researching indicators of compromise during relevant investigations.

### 4. SOC Playbooks
Practical investigation checklists for common security alerts and incidents.

## Tools and Technologies

Tools will be selected according to each investigation. Planned technologies include:

- Linux and Python
- Windows Event Logs (EVTX)
- Hayabusa
- Wireshark
- Splunk (subject to hardware feasibility)
- SQLite
- Git and GitHub

## Investigation Methodology

Each case will follow a consistent investigation process:

1. Alert identification
2. Initial triage
3. Evidence collection
4. Timeline analysis
5. Investigation and correlation
6. Verdict and severity assessment
7. Response recommendations
8. Documentation and lessons learned

## Evidence and Data Sources

Investigations will use public security datasets and controlled lab-generated events.

Each case will clearly identify its data provenance. No real organizational or personal data will be published.

## Project Status

Currently in the foundation stage. Repository structure and investigation documentation are being established.

## Disclaimer

This project is intended for cybersecurity education and defensive security analysis. All lab activities are performed in controlled environments or against authorized data sources.
