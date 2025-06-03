<img width="450" src="https://github.com/user-attachments/assets/7724a75a-01f9-4f0e-9247-19ea30e355d4" alt="Hacker with laptop"/>

# Threat Hunt Report: Brute Force Attack Investigation
- [Scenario Creation](https://github.com/TsumaA/threat-hunting-scenario-brute-force-investigation/blob/main/threat-hunting-scenario-brute-force-attack.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Internet-exposed honeypot VM

## Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

During the time the devices were unknowingly exposed to the internet, it's possible that someone could have actually brute-force logged into some of them since some of the older devices do not have account lockout configured for excessive failed login attempts.

### High-Level Brute Force Attack Discovery Plan

- **Check `DeviceLogonEvents`** for any excessive failed login attempts from external IP addresses.
- **Check `DeviceInfo`** for any devices that are internet-facing.
- **Check `DeviceLogonEvents`** for any successful logins following patterns of brute force attempts.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table for Failed Login Attempts

Searched for devices with the highest number of failed login attempts from external IP addresses. Discovered that the device "abe-mde-est" had received significant brute force attacks from multiple IP addresses, with the top attacking IPs generating hundreds of failed login attempts each. The top 5 most aggressive attackers were `20.64.248.197`, `92.63.197.9`, `94.102.52.73`, `185.243.96.107`, and `185.156.73.169`.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```
![Screenshot 2025-06-03 102559](https://github.com/user-attachments/assets/5546023c-ed24-498c-a2ac-962c249d229a)

---

### 2. Searched the `DeviceInfo` Table for Internet-Facing Status

Searched for devices that were internet-facing to confirm exposure. The device "abe-mde-est" was confirmed to be internet-facing for an extended period ending at `2025-05-22T17:17:38.7103366Z`, making it vulnerable to external attacks during this exposure window.

**Query used to locate events:**

```kql
DeviceInfo
| where DeviceName == "abe-mde-est"
| where IsInternetFacing == true
| order by Timestamp desc
```

---

### 3. Searched the `DeviceLogonEvents` Table for Successful Logins from Attacking IPs

Searched for any successful logins from the IP addresses that had conducted the most failed login attempts. The investigation revealed that despite hundreds of brute force attempts from the top attacking IPs, none of these external attackers successfully authenticated to the system.

**Query used to locate events:**

```kql
let RemoteIPsInQuestion = dynamic(["20.64.248.197","92.63.197.9", "94.102.52.73", "185.243.96.107", "185.156.73.169", "185.243.96.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

---

### 4. Searched the `DeviceLogonEvents` Table for Brute Force Success Patterns

Searched for IP addresses that had both failed and successful login attempts to identify potential brute force successes. The analysis showed that while there were legitimate successful logins for the "labuser" account, these came from different IP addresses than the attacking ones and showed no pattern of preceding failed attempts.

**Query used to locate events:**

```kql
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by ActionType, RemoteIP, DeviceName
| order by FailedLogonAttempts;
let SuccessfulLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by ActionType, RemoteIP, DeviceName, AccountName
| order by SuccessfulLogons;
FailedLogons
| join SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

---

### 5. Searched the `DeviceLogonEvents` Table for Legitimate Account Activity

Searched for successful network logins to verify if any brute force attempts succeeded for specific accounts. The investigation confirmed that all successful logins for the "labuser" account came from legitimate sources with zero preceding failed attempts from the same IPs, indicating the brute force attacks were unsuccessful and that no password guessing occurred for this account.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "abe-mde-est"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
![Screenshot 2025-06-03 102655](https://github.com/user-attachments/assets/01fd5668-c765-48b3-a3b9-4423b9ada10b)

---

## Chronological Event Timeline

### 1. Internet Exposure Window
- **Timestamp:** `2025-05-22T17:17:38Z` (last confirmed exposure)
- **Event:** Device "abe-mde-est" confirmed as internet-facing for several days, making it discoverable and vulnerable to external attacks.
- **Action:** Internet exposure detected through network configuration.
- **Impact:** Attack surface created for external threat actors.

### 2. Brute Force Attack Campaign - Multiple External IPs
- **Timestamp:** Multiple timestamps over several days
- **Event:** Coordinated brute force attacks detected from multiple IP addresses including `20.64.248.197`, `92.63.197.9`, `94.102.52.73`, `185.243.96.107`, `185.156.73.169`, and `185.243.96.116`.
- **Action:** Hundreds of failed login attempts recorded per attacking IP.
- **Target Accounts:** Various account names systematically attempted.
- **Attack Pattern:** Password spraying and credential stuffing techniques observed.



### 3. Legitimate User Activity - Normal Authentication Patterns
- **Timestamp:** Various timestamps throughout exposure period
- **Event:** Legitimate successful logins detected for the "labuser" account from authorized IP addresses with no correlation to attacking IPs.
- **Action:** Normal authentication patterns observed from trusted sources.
- **Pattern:** Zero failed attempts preceding successful logins from legitimate IPs.
- **Account Security:** No evidence of account compromise.

### 4. Attack Failure Analysis
- **Timestamp:** Investigation period analysis
- **Event:** Cross-correlation analysis revealed complete failure of all brute force attempts with zero successful authentications from any attacking IP addresses.
- **Action:** Brute force campaign confirmed as unsuccessful.
- **Defense Effectiveness:** Strong password policies prevented breach despite sustained attack.


---

## Summary

The investigation on device "abe-mde-est" revealed extensive brute force attack campaigns from multiple external IP addresses during its internet-facing exposure period. Despite hundreds of systematic failed login attempts using password spraying and credential stuffing techniques, no evidence was found of successful unauthorized access. The legitimate "labuser" account showed normal authentication patterns from authorized sources with no signs of compromise. The device's internet-facing exposure created an attractive attack surface for external threat actors, but proper password policies and account security measures successfully prevented all breach attempts.

---

## Response Taken

The device "abe-mde-est" was secured by removing internet exposure and implementing additional monitoring. All attacking IP addresses were blocked at the network perimeter. Account lockout policies were reviewed and strengthened where necessary to prevent future sustained attack attempts.

---
