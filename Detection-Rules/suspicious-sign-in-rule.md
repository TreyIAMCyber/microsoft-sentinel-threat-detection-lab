# Suspicious Sign-In Detection Rule

## Rule Name

Multiple Failed Entra ID Sign-Ins

## Purpose

This Microsoft Sentinel Analytics Rule detects repeated failed Microsoft Entra ID authentication attempts that may indicate password guessing or other suspicious authentication activity.

## Data Source

- Microsoft Entra ID Sign-in Logs
- Sentinel `SigninLogs` table

## Detection Logic

The rule identifies authentication events with ResultType `50126`, indicating invalid username or password authentication attempts.

The activity is grouped by:

- UserPrincipalName
- IPAddress

The rule generates a detection when five or more failed authentication attempts are identified for the same user and source IP.

## KQL Query

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

## Rule Configuration

| Setting | Configuration |
|---|---|
| Rule Type | Scheduled Analytics Rule |
| Severity | Medium |
| Frequency | Every 5 minutes |
| Lookup Period | Previous 10 minutes |
| Threshold | 5 or more failed attempts |
| Data Source | Microsoft Entra ID Sign-in Logs |
| Table | `SigninLogs` |

## Entity Mapping

The rule maps the following entities:

### Account

- Entity Type: Account
- Identifier: FullName
- Value: `UserPrincipalName`

### IP Address

- Entity Type: IP
- Identifier: Address
- Value: `IPAddress`

Entity mapping allows Microsoft Sentinel to associate the alert with the affected user account and source IP address.

## MITRE ATT&CK

**T1110.001 — Password Guessing**

The detection is associated with Password Guessing because repeated failed authentication attempts can indicate attempts to discover or validate user credentials.

## Validation

The detection was validated by generating five failed authentication attempts against the dedicated lab account.

The Analytics Rule successfully detected the activity and generated a Microsoft Sentinel incident.

The resulting incident successfully displayed both the affected user and source IP as entities.

## Investigation Outcome

The generated incident was investigated using Microsoft Sentinel's incident overview, entity information, investigation graph, and authentication data.

The activity was intentionally generated as part of the lab validation process and was determined to be simulated security activity rather than an actual account compromise.

The incident was documented and closed after validation.
