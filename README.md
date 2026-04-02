Cloud SOC lab in Azure using Microsoft Sentinel to detect brute-force login attempts with Windows Security logs and KQL.
# Azure SOC Lab – Brute Force Detection

## 📌 Overview
This project demonstrates how to build a cloud-based Security Operations Center (SOC) lab in Azure using Microsoft Sentinel. The lab focuses on detecting brute-force login attempts using Windows Security Event Logs and KQL queries.

---

## 🛠️ Technologies Used
- Microsoft Azure
- Microsoft Sentinel (SIEM)
- Log Analytics Workspace
- Windows Virtual Machine
- Kusto Query Language (KQL)

---

## 🔍 Detection Use Case
**Brute Force Login Attempts (Event ID 4625)**

Attackers often attempt multiple failed logins to gain unauthorized access. This lab detects suspicious activity by analyzing repeated failed login attempts.

---

## 🧪 KQL Query Used
```kql
Event
| where EventLog == "Security"
| where EventID == 4625
| summarize FailedAttempts = count() by bin(TimeGenerated, 5m)
| where FailedAttempts > 5

---

## 📸 Lab Screenshots

### Log Data
![Logs](screenshots/SOC%20lab%201.png)

### Query Results
![Query](screenshots/SOC%20lab%202.png)

### Timechart Visualization
![Chart](screenshots/SOC%20lab%203.png)

### Alert Rule
![Alert](screenshots/SOC%20lab%20primary%20alert%20rule.png)

---

## 🎯 Outcome
- Ingested Windows Security logs into Microsoft Sentinel
- Built KQL queries to detect failed login attempts
- Created an analytics rule for brute-force detection
- Visualized attack patterns using timecharts
