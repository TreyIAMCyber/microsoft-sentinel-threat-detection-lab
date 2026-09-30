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
| where ResultType == 50126
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

Additional queries will be added as the investigation progresses.

---

## Detection Rule

A Microsoft Sentinel Analytics Rule was created to detect repeated failed Microsoft Entra ID authentication attempts.

The rule:

- Uses the `SigninLogs` table
- Identifies failed authentication events with ResultType `50126`
- Groups activity by user and source IP address
- Triggers when five or more failed attempts are detected
- Runs every 5 minutes
- Looks back over the previous 10 minutes
- Maps the affected user and source IP as incident entities
- Generates a Sentinel incident for investigation

The detection was successfully validated by generating five failed authentication attempts against the lab account.

---

## Incident Investigation

The generated Microsoft Sentinel incident was investigated using the incident overview, entities, investigation graph, and authentication data.

The investigation included:

- Identification of the affected user
- Identification of the source IP address
- Review of failed authentication activity
- Review of successful authentication activity
- Authentication timeline analysis
- Review of related authentication result codes
- Entity correlation within Microsoft Sentinel
- Assessment of whether the activity represented a potential compromise

The Sentinel investigation graph successfully correlated the affected user and source IP with the generated incident.

The activity was intentionally generated as part of the lab validation process and was therefore determined to be simulated security activity rather than an actual compromise.

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

The detection is aligned with:

**T1110.001 — Password Guessing**

The technique was selected because the lab simulates repeated failed authentication attempts against a user account.

The mapping demonstrates how authentication-based detections can be associated with relevant MITRE ATT&CK techniques during SOC analysis.
---

## Results

The detection was successfully validated end-to-end.

Results included:

- Microsoft Entra ID authentication logs successfully ingested into Sentinel
- KQL successfully identified repeated failed authentication activity
- A custom Microsoft Sentinel Analytics Rule was created
- The rule successfully triggered after simulated failed authentication attempts
- A Sentinel security incident was generated
- The affected user and source IP were successfully mapped as entities
- The investigation graph correlated the entities with the alert
- Authentication activity was reviewed to establish the investigation timeline
- Investigation findings and response actions were documented
- The incident was classified and closed after validation

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

This lab provided hands-on experience building an authentication threat detection workflow in Microsoft Sentinel.

Key lessons included:

- Authentication logs provide valuable telemetry for detecting account-based threats.
- KQL can be used to transform raw authentication events into actionable detections.
- Entity mapping improves incident investigation by connecting alerts to users and IP addresses.
- Detection rules should be validated with controlled test activity before being considered operational.
- Reviewing the complete authentication timeline is important when determining whether failed authentication activity resulted in potential account compromise.
- Effective SOC investigations require both technical evidence and clear documentation.

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
