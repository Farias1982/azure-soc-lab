# Playbook Deployment Guide – Brute Force Response

This guide walks through deploying the `brute-force-response.json` Logic App playbook into your Azure environment and connecting it to a Microsoft Sentinel analytics rule.

---

## Prerequisites

- Microsoft Sentinel enabled on your Log Analytics Workspace
- A Windows VM with an attached Network Security Group (NSG)
- An Office 365 / Microsoft 365 account for email notifications
- Contributor or Owner role on the resource group

---

## Step 1 – Deploy the ARM Template

1. In the Azure Portal, search for **Deploy a custom template**
2. Click **Build your own template in the editor**
3. Paste the contents of [`brute-force-response.json`](brute-force-response.json)
4. Click **Save**, then fill in the parameters:

| Parameter | Value |
|---|---|
| `PlaybookName` | `BruteForce-Response-Playbook` |
| `NotificationEmail` | Your email address |
| `SubscriptionId` | Your Azure Subscription ID |
| `ResourceGroupName` | `soc-lab-rg` |
| `NSGName` | Name of your VM's NSG (e.g. `soc-lab-vm-nsg`) |

5. Click **Review + Create** → **Create**

---

## Step 2 – Authorize API Connections

After deployment, three API connections need to be authorized:

### Microsoft Sentinel Connection
1. Go to the deployed resource group → find `azuresentinel` API connection
2. Click **Edit API connection** → **Authorize** → sign in with your Azure account
3. Click **Save**

### Office 365 Connection
1. Find the `office365` API connection in the resource group
2. Click **Edit API connection** → **Authorize** → sign in with your Microsoft 365 account
3. Click **Save**

### Azure Resource Manager Connection
1. Find the `arm` API connection
2. Click **Edit API connection** → **Authorize** → sign in
3. Click **Save**

---

## Step 3 – Assign NSG Write Permission to the Logic App

The playbook needs permission to add deny rules to your NSG.

1. Go to your NSG → **Access Control (IAM)** → **Add role assignment**
2. Role: **Network Contributor**
3. Assign access to: **Managed Identity**
4. Select the Logic App: `BruteForce-Response-Playbook`
5. Click **Save**

---

## Step 4 – Attach the Playbook to a Sentinel Analytics Rule

1. In Microsoft Sentinel → **Analytics** → open your brute force detection rule
2. Click **Edit** → go to the **Automated response** tab
3. Under **Alert automation**, click **Add new**
4. Select `BruteForce-Response-Playbook`
5. Click **Apply** → **Save**

The playbook will now fire automatically every time Sentinel creates an incident from the brute force detection rule.

---

## Step 5 – Test the Playbook

1. Trigger a brute force detection by generating failed logins on your VM
2. Wait for Sentinel to create an incident (up to 10 minutes based on rule schedule)
3. Verify:
   - [ ] Email notification received with incident details
   - [ ] NSG deny rule created for the attacker IP (check NSG → Inbound security rules)
   - [ ] Sentinel incident has an automated comment confirming the IP block

---

## How It Works

```
Brute force activity on VM
        ↓
Windows Security Log → Event ID 4625
        ↓
Log Analytics Workspace ingests events
        ↓
Sentinel Analytics Rule fires (every 5 min)
        ↓
Incident created in Sentinel
        ↓
Logic App Playbook triggered
        ↙              ↘
Email alert        NSG deny rule added
sent to SOC        blocking attacker IP
        ↓
Sentinel incident comment added confirming response
```

---

## Troubleshooting

| Issue | Resolution |
|---|---|
| Email not received | Re-authorize the Office 365 API connection |
| NSG rule not created | Verify the Logic App's managed identity has Network Contributor on the NSG |
| Playbook not triggering | Confirm the playbook is attached under the analytics rule's Automated response tab |
| `Forbidden` error in Logic App run history | Check IAM permissions on the subscription and NSG |
