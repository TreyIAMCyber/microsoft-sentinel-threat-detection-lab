# Microsoft Sentinel Threat Detection Lab

Hands-on Microsoft Sentinel lab demonstrating practical skills in **security monitoring, KQL, threat detection, incident investigation, and incident response**.

## Project Overview

This project simulates a Security Operations Center (SOC) investigation using **Microsoft Sentinel** and Microsoft Entra ID authentication data.

The objective is to identify suspicious authentication activity, investigate the associated entities and events, create a detection rule, and document the investigation and recommended response actions.

This project was created as a practical demonstration of skills aligned with the **Microsoft SC-200: Microsoft Security Operations Analyst** certification.

---

## Objectives

* Configure a Microsoft Sentinel environment
* Connect Microsoft Entra ID authentication logs
* Use Kusto Query Language (KQL) to investigate security events
* Identify suspicious authentication patterns
* Investigate users, IP addresses, locations, and sign-in activity
* Create a Microsoft Sentinel analytics rule
* Generate and investigate a security incident
* Map relevant activity to the MITRE ATT&CK framework
* Document investigation findings and response recommendations

---

## Technologies & Tools

| Technology                 | Purpose                                   |
| -------------------------- | ----------------------------------------- |
| Microsoft Sentinel         | SIEM and security operations              |
| Microsoft Entra ID         | Identity and authentication data          |
| Log Analytics              | Log collection and analysis               |
| Kusto Query Language (KQL) | Security investigation and detection      |
| MITRE ATT&CK               | Threat behavior classification            |
| GitHub                     | Project documentation and version control |

---

## Lab Architecture

```text
Microsoft Entra ID
        │
        │ Authentication Events
        ▼
Log Analytics Workspace
        │
        ▼
Microsoft Sentinel
        │
        ├── KQL Queries
        │
        ├── Analytics Rules
        │
        ▼
Security Incident
        │
        ▼
Investigation
        │
        ├── User Analysis
        ├── IP Analysis
        ├── Sign-In Analysis
        └── Timeline Analysis
        │
        ▼
Incident Response
```

---

## Skills Demonstrated

### Security Monitoring

* Authentication event monitoring
* Sign-in analysis
* Suspicious activity identification
* Security incident investigation

### KQL

* Filtering security events
* Aggregating authentication activity
* Identifying failed authentication patterns
* Investigating successful authentication following failed attempts
* Extracting relevant security entities
* Sorting and correlating events by time

### Microsoft Sentinel

* Sentinel workspace configuration
* Data connector configuration
* Analytics rule creation
* Incident investigation
* Entity investigation

### Incident Response

* Alert validation
* Incident investigation
* Evidence collection
* Threat assessment
* Recommended containment and remediation actions

---

## Investigation Scenario

> A user account generates multiple failed authentication attempts followed by a successful sign-in. The SOC analyst must determine whether the activity represents a potential account compromise.

The investigation will examine:

* Number of failed authentication attempts
* Successful authentication events
* Source IP addresses
* Geographic location
* Applications accessed
* Authentication results
* Timeline of activity
* Potential indicators of compromise

---

## KQL Queries

The `KQL/` directory contains queries developed during the investigation.

### Failed Sign-In Detection

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count() by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

Additional queries will be added as the investigation progresses.

---

## Detection Rule

The `Detection-Rules/` directory contains documentation for the Microsoft Sentinel analytics rule created during the lab.

The rule will be designed to identify suspicious authentication behavior and generate a Sentinel incident for investigation.

---

## Incident Investigation

The `Incident-Response/` directory contains the investigation documentation, including:

* Incident summary
* Detection source
* Affected entities
* Timeline
* Indicators of compromise
* Investigation findings
* MITRE ATT&CK mapping
* Recommended response actions
* Lessons learned

---

## Screenshots

Screenshots documenting the lab environment and investigation will be stored in the `Screenshots/` directory.

Planned evidence includes:

1. Microsoft Sentinel workspace
2. Log Analytics workspace
3. Microsoft Entra ID data connector
4. KQL investigation query
5. Analytics rule configuration
6. Generated security incident
7. Incident investigation
8. Investigation findings

Sensitive information such as credentials, tokens, tenant identifiers, and other private information will be removed or redacted before publication.

---

## MITRE ATT&CK Mapping

Relevant activity identified during the investigation will be mapped to the appropriate MITRE ATT&CK techniques.

Potential techniques will be determined based on the actual evidence discovered during the investigation rather than assumed in advance.

---

## Results

*To be completed after the lab investigation.*

The final results will document:

* Detection outcome
* Investigation findings
* Identified indicators
* Severity assessment
* MITRE ATT&CK techniques
* Recommended response
* Lessons learned

---

## Lessons Learned

*To be completed after the lab.*

This section will summarize technical findings and practical lessons learned while configuring Sentinel, writing KQL queries, investigating authentication activity, and developing a detection workflow.

---

## Repository Structure

```text
microsoft-sentinel-threat-detection-lab/
│
├── README.md
│
├── KQL/
│   ├── failed-sign-in-detection.kql
│   ├── suspicious-sign-in-investigation.kql
│   └── sign-in-analysis.kql
│
├── Detection-Rules/
│   └── suspicious-sign-in-rule.md
│
├── Incident-Response/
│   └── incident-investigation.md
│
├── Screenshots/
│
└── Documentation/
    └── lab-notes.md
```

---

## Disclaimer

This project is a personal cybersecurity training and portfolio project created to demonstrate practical security operations skills.

No production systems or unauthorized environments are targeted as part of this project.
