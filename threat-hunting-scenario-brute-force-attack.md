# Brute Force Attack Scenario Creation

<img width="200" src="https://github.com/user-attachments/assets/7724a75a-01f9-4f0e-9247-19ea30e355d4" alt="Hacker with laptop"/>

## Overview

This document outlines the process used to create a realistic brute force attack scenario for threat hunting training purposes. The scenario generates authentic attack data by exposing a Windows VM to the internet and allowing automated attackers to discover and target the system.

## Steps to Create the Scenario

### Step 1: Virtual Machine Setup
- Created a Windows 10 VM in Microsoft Azure cloud environment
- Named the VM "abe-mde-est" for identification purposes
- Configured basic user account "labuser" with standard permissions
- **Important:** Used strong passwords (NOT weak credentials like `labuser/Cyberlab123!`)

### Step 2: Microsoft Defender for Endpoint Onboarding
- Downloaded MDE onboarding package from Microsoft 365 Defender portal
- Executed onboarding script on the target VM
- Verified connectivity and confirmed log ingestion was working
- Ensured all required data sources (`DeviceLogonEvents`, `DeviceInfo`, `DeviceNetworkEvents`) were active

### Step 3: Internet Exposure Configuration
- Configured Azure networking to make the VM internet-facing
- Opened RDP port (3389) to allow external access attempts
- Verified the VM was discoverable from external networks
- Confirmed internet connectivity and external accessibility

### Step 4: Controlled Exposure Period
- Left the VM internet-exposed for **90+ minutes initially**
- Extended exposure over **several days** to capture diverse attack patterns
- Monitored MDE logs continuously for incoming attack activity
- Allowed sufficient time for automated scanners and bots to discover the system

### Step 5: Attack Data Collection
- External IP addresses began scanning and discovering the exposed RDP service within hours
- Automated brute force tools started attempting login combinations
- Multiple distinct IP addresses launched coordinated attack campaigns
- Hundreds of failed login attempts were recorded across different source IPs

### Step 6: Scenario Validation
- Confirmed comprehensive logging of all attack attempts
- Verified no successful unauthorized access occurred
- Validated that strong passwords prevented actual compromise
- Documented complete timeline of exposure and attack patterns

## IOCs Detected During Scenario Creation

| IOC Type | IOC Value | Description | Data Source |
|----------|-----------|-------------|-------------|
| IP Address | 20.64.248.197 | Top attacking IP with hundreds of failed login attempts | DeviceLogonEvents |
| IP Address | 92.63.197.9 | Second highest volume of brute force attempts | DeviceLogonEvents |
| IP Address | 94.102.52.73 | Persistent attacker with sustained campaign | DeviceLogonEvents |
| IP Address | 185.243.96.107 | Geographic diversity in attack sources | DeviceLogonEvents |
| IP Address | 185.156.73.169 | Automated brute force tool usage | DeviceLogonEvents |
| Event Type | LogonFailed | High volume of failed authentication attempts | DeviceLogonEvents |
| Event Type | IsInternetFacing=true | Confirmation of internet exposure | DeviceInfo |
| Port | 3389 (RDP) | Primary attack vector for brute force attempts | DeviceNetworkEvents |
| Attack Pattern | Password Spraying | Multiple accounts targeted with common passwords | DeviceLogonEvents |
| Attack Pattern | Credential Stuffing | Systematic username/password combinations | DeviceLogonEvents |

## Related Queries for Scenario Detection

### Query 1: Detect High Volume Failed Logins
```kql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| where Attempts > 50
| order by Attempts desc
```

### Query 2: Identify Internet-Facing Systems
```kql
DeviceInfo
| where IsInternetFacing == true
| summarize arg_max(Timestamp, *) by DeviceName
| project DeviceName, Timestamp, IsInternetFacing, PublicIP
```

### Query 3: Correlate Failed and Successful Attempts
```kql
let FailedLogons = DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count() by RemoteIP, DeviceName;
let SuccessfulLogons = DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogins = count() by RemoteIP, DeviceName, AccountName;
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP, DeviceName
| where FailedAttempts > 10
| project RemoteIP, DeviceName, FailedAttempts, SuccessfulLogins, AccountName
```

### Query 4: Timeline Analysis
```kql
DeviceLogonEvents
| where DeviceName == "abe-mde-est"
| where isnotempty(RemoteIP)
| summarize Events = count() by bin(Timestamp, 1h), ActionType
| render timechart
```

### Query 5: Geographic Attack Distribution
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP
| where Attempts > 100
| project RemoteIP, Attempts
| order by Attempts desc
```

## Scenario Outcomes

### Attack Statistics Generated
- **Duration of Exposure:** Several days
- **Number of Attacking IPs:** 15+ distinct source addresses
- **Failed Login Attempts:** 500+ total attempts
- **Success Rate:** 0% (no unauthorized access)
- **Geographic Distribution:** Global attack sources identified

### Security Validation
- Strong password policies successfully prevented all breach attempts
- Comprehensive logging captured complete attack timeline
- Real-world attack patterns authentically reproduced
- Multiple attack techniques observed (password spraying, credential stuffing)

## Safety Considerations

### Security Measures Implemented
- **Strong Authentication:** Used complex passwords to prevent actual compromise
- **Continuous Monitoring:** MDE logging captured all activity
- **Controlled Environment:** Azure cloud isolation and monitoring
- **Time-Limited Exposure:** Managed exposure duration for safety
- **Incident Response Ready:** Prepared containment procedures

### Risk Mitigation
- No sensitive data stored on the target VM
- Regular monitoring for signs of successful compromise
- Automated alerting for unexpected activity
- Network segmentation to prevent lateral movement
- Documented recovery procedures

---

## Created By:
- **Author Name**: Abraham Tsuma
- **Author Contact**: https://www.linkedin.com/in/abraham-t-992ba810a
- **Date**: June, 3, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `June 3, 2025`  | `Abraham Tsuma`   
