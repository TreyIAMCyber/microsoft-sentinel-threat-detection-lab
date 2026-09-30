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
