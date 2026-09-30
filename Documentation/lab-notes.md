# Microsoft Sentinel Threat Detection Lab Notes

## Lab Purpose

This lab was created to demonstrate a practical SOC workflow using Microsoft Sentinel and Microsoft Entra ID authentication data.

The lab focused on collecting authentication telemetry, analyzing sign-in activity with KQL, creating a detection rule, generating a security incident, investigating the incident, and documenting the response.

## Environment

### Microsoft Azure

- Azure Resource Group
- Log Analytics Workspace
- Microsoft Sentinel

### Microsoft Entra ID

- Entra ID authentication logs
- Dedicated lab user account
- Sign-in activity generated for detection testing

## Data Collection

Microsoft Entra ID Sign-in Logs were connected to the Microsoft Sentinel environment.

The `SigninLogs` table was used throughout the investigation to analyze authentication activity.

Authentication events were reviewed using KQL to identify:

- Failed sign-ins
- Successful sign-ins
- Source IP addresses
- Authentication result codes
- Applications
- Authentication timestamps

## Authentication Testing

A dedicated lab account was used to generate controlled authentication activity.

Multiple failed authentication attempts were intentionally generated to validate the detection.

Successful authentication activity was also generated to provide additional events for timeline analysis.

## Detection Development

A KQL detection was developed to identify repeated failed authentication attempts.

The detection:

- Uses the `SigninLogs` table
- Filters for ResultType `50126`
- Groups activity by user and source IP
- Counts failed authentication attempts
- Requires five or more failed attempts

## Analytics Rule

The KQL detection was implemented as a Microsoft Sentinel Scheduled Analytics Rule.

### Configuration

- Rule Type: Scheduled Analytics Rule
- Frequency: Every 5 minutes
- Lookup Period: Previous 10 minutes
- Threshold: Five or more failed attempts
- Data Source: Microsoft Entra ID Sign-in Logs
- Entity Mapping: Account and IP Address

## Detection Validation

The detection was validated by generating five failed authentication attempts against the lab account.

The Analytics Rule successfully identified the activity and generated a Microsoft Sentinel security incident.

The resulting incident contained both the affected user and source IP as entities.

## Incident Investigation

The generated incident was investigated using:

- Incident overview
- Alert details
- User entity
- IP entity
- Investigation graph
- Authentication data
- Authentication timeline

The investigation established the sequence of authentication activity and evaluated whether the activity indicated potential account compromise.

## Investigation Findings

The repeated failed authentication activity successfully triggered the detection.

The affected user and source IP were successfully correlated with the incident.

Additional authentication events, including successful authentication activity, were reviewed as part of the authentication timeline.

Because the activity was intentionally generated for this controlled lab, it was determined to be simulated security activity rather than an actual compromise.

## MITRE ATT&CK

The detection was mapped to:

**T1110.001 — Password Guessing**

This technique was selected because repeated failed authentication attempts can indicate attempts to discover or validate credentials.

## Incident Response

The incident was documented with the investigation findings and response recommendations.

In a production environment, recommended actions would include:

- Validate whether authentication activity is authorized
- Review source IP reputation and location
- Review successful authentication following failed attempts
- Verify MFA activity
- Investigate additional account activity
- Reset credentials if compromise is suspected
- Revoke active sessions when appropriate
- Continue monitoring for additional suspicious activity

## Final Outcome

The lab successfully demonstrated an end-to-end Microsoft Sentinel SOC workflow:

**Log Collection → KQL Analysis → Detection → Alert → Incident → Entity Correlation → Investigation → Response → Closure**

## Skills Demonstrated

- Microsoft Sentinel
- Microsoft Entra ID
- KQL
- SIEM
- Authentication Monitoring
- Threat Detection
- Incident Investigation
- Entity Correlation
- MITRE ATT&CK
- Incident Response
- Security Documentation
