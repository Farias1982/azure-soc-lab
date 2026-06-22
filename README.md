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

## 🚀 Lab Setup & Deployment

Follow these steps to reproduce this lab in your own Azure environment.

### Prerequisites
- An active Azure subscription (free tier works)
- Azure CLI or access to the Azure Portal
- Basic familiarity with Azure resource groups and virtual machines

---

### Step 1 – Create a Resource Group
In the Azure Portal, create a new Resource Group to contain all lab resources.

```
Name:     soc-lab-rg
Region:   East US (or your nearest region)
```

---

### Step 2 – Deploy a Windows Virtual Machine
Create a Windows Server VM inside `soc-lab-rg`. This machine will generate the security events.

```
OS:       Windows Server 2022
Size:     Standard_B2s (cost-effective for a lab)
Username: labadmin
RDP:      Enable port 3389 (for simulating brute force attempts)
```

> ⚠️ Leaving RDP open to the internet will attract real brute force attempts within minutes — this is intentional for the lab. Restrict or delete the VM when done.

---

### Step 3 – Create a Log Analytics Workspace
Microsoft Sentinel requires a Log Analytics Workspace to store and query log data.

```
Name:     soc-lab-workspace
Region:   Same as your resource group
```

---

### Step 4 – Enable Microsoft Sentinel
1. Search for **Microsoft Sentinel** in the Azure Portal
2. Click **Create** and attach it to `soc-lab-workspace`
3. Sentinel is now active and ready to ingest data

---

### Step 5 – Connect the Windows VM Data Connector
1. In Sentinel, go to **Content Hub** and install **Windows Security Events**
2. Go to **Data Connectors** → **Windows Security Events via AMA**
3. Create a **Data Collection Rule (DCR)** and target your Windows VM
4. Select **All Security Events** to capture Event ID 4625, 4624, and 4740

---

### Step 6 – Simulate Brute Force Activity
To generate log data, either:
- Wait for organic internet scanners to hit the open RDP port (usually within 15–30 minutes), or
- Manually trigger failed logins by entering wrong credentials repeatedly via RDP

---

### Step 7 – Run KQL Detection Queries
Once logs appear in Sentinel (allow 5–15 minutes for ingestion), open **Logs** and run the queries from the [`queries/`](queries/) folder:

| Query | Purpose |
|---|---|
| [`01_brute_force_detection.kql`](queries/01_brute_force_detection.kql) | Confirm failed login volume |
| [`02_brute_force_with_source_ip.kql`](queries/02_brute_force_with_source_ip.kql) | Identify attacker IPs |
| [`03_successful_login_after_failures.kql`](queries/03_successful_login_after_failures.kql) | Detect successful compromise |
| [`04_account_lockout_detection.kql`](queries/04_account_lockout_detection.kql) | Surface locked-out accounts |

---

### Step 8 – Create an Analytics Rule (Alert)
1. In Sentinel, go to **Analytics** → **Create** → **Scheduled query rule**
2. Paste the query from `01_brute_force_detection.kql`
3. Set the rule to run every **5 minutes**, looking back **5 minutes**
4. Set alert threshold to trigger when results are **greater than 0**
5. Assign severity: **Medium** or **High**

This creates automated incidents in Sentinel whenever brute force activity is detected.

---

## 🔍 Detection Use Cases

| # | Query File | Event ID | Description |
|---|---|---|---|
| 1 | [`01_brute_force_detection.kql`](queries/01_brute_force_detection.kql) | 4625 | Detects repeated failed logins in 5-minute windows |
| 2 | [`02_brute_force_with_source_ip.kql`](queries/02_brute_force_with_source_ip.kql) | 4625 | Enriches failed logins with source IP and targeted accounts |
| 3 | [`03_successful_login_after_failures.kql`](queries/03_successful_login_after_failures.kql) | 4625 + 4624 | Identifies successful logins following repeated failures — high-confidence brute force indicator |
| 4 | [`04_account_lockout_detection.kql`](queries/04_account_lockout_detection.kql) | 4740 | Surfaces locked-out accounts and the machines triggering lockouts |

---

## 🧪 Core KQL Query

```kql
// Brute Force Detection – 5+ failures in a 5-minute window
Event
| where EventLog == "Security"
| where EventID == 4625
| summarize FailedAttempts = count() by bin(TimeGenerated, 5m)
| where FailedAttempts > 5
| order by FailedAttempts desc
```

> See the [`queries/`](queries/) folder for all detection queries with inline documentation.

---

## 📸 Lab Screenshots

### Log Data
![Logs](screenshots/soc-lab-1.png)
![Query](screenshots/soc-lab-2.png)
![Chart](screenshots/soc-lab-3.png)
![Alert](screenshots/alert-rule.png)

---

## 🎯 Outcome & Lessons Learned

### What Was Built
- A fully functional cloud SOC lab in Azure with real log ingestion, KQL-based threat detection, and automated alerting through Microsoft Sentinel
- A detection pipeline covering the full brute force attack chain: failed attempts → account lockout → potential successful compromise
- Four production-quality KQL queries with inline documentation, each targeting a distinct phase of the attack

### Key Takeaways
- **Log ingestion lag is real.** There is typically a 5–15 minute delay between an event occurring on the VM and it appearing in the Log Analytics Workspace. Tuning alert lookback windows to account for this is critical to avoid missed detections.
- **RDP is constantly targeted.** Within minutes of opening port 3389 to the internet, automated scanners begin attempting logins. This made generating realistic test data straightforward and highlighted how exposed default configurations are.
- **KQL is powerful but requires precision.** Extracting fields like source IP from raw XML EventData requires careful use of `parse_xml()`. Small errors in field indexing return null values silently, making query validation essential.
- **Alert threshold tuning matters.** Setting the failure threshold too low creates alert fatigue; too high and real attacks slip through. Starting at 5 failures per 5 minutes and adjusting based on baseline noise is a practical approach.

### What I Would Add Next
- Threat intelligence integration using Microsoft Sentinel's **TI Map** to automatically flag known malicious IPs
- A **watchlist** of known-good admin IPs to reduce false positives
- **Playbooks (Logic Apps)** to auto-respond to incidents — e.g., blocking an IP via NSG rule when brute force is confirmed
- Expansion to Linux VMs to cover SSH-based brute force (Event log: `/var/log/auth.log`)
