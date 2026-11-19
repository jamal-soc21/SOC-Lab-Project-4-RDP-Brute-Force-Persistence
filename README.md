# 🛡️ SOC Lab Project 1: RDP Brute Force & Persistence Detection

## 📋 Project Overview
This project demonstrates a complete attack chain (Brute Force → Compromise → Persistence) and analyzes its detection in a Wazuh SIEM environment with Sysmon integration. It highlights a critical detection gap where a persistence mechanism is logged but classified at a low severity level, potentially bypassing analyst attention.

## 🎯 Attack Scenario
- **Attacker:** Kali Linux (192.168.1.13)
- **Target:** Windows 11 (192.168.1.12, Hostname: JAMAL)
- **Account:** BruteTarget
- **Tools Used:** NetExec (Brute Force), Remmina (RDP Access), schtasks (Persistence)

## 🔍 Investigation Timeline

### Phase 1: Brute Force Attack
- **Tool:** NetExec (`netexec rdp 192.168.1.12 -u BruteTarget -p pw.txt`)
- **Result:** 5 failed attempts (Event ID 4625), followed by 1 successful logon (Event ID 4624, Logon Type 10).
- **Wazuh Detection:** ✅ Successfully detected and alerted (Level 5+).

### Phase 2: Post-Exploitation & Persistence
- **Action:** Created a scheduled task to maintain access.
- **Command:** `schtasks /create /tn WinUpdater /tr "cmd.exe /c calc.exe" /sc minute /mo 5 /f`
- **Result:** Task created successfully (verified via `schtasks /query`).
- **Wazuh Detection:** ⚠️ **Detected but Low Severity (Level 4)**.

## ⚠️ Critical Finding: Detection Gap Analysis

### What Happened?
The scheduled task creation was detected by Wazuh via Sysmon, but classified as **Level 4** (low severity). This means it does not trigger immediate analyst attention or automated high-severity response rules.

### Technical Details
- **Event Source:** Sysmon Event ID 1 (Process Creation)
- **MITRE ATT&CK Mapping:** T1053.005 (Scheduled Task)
- **Process:** `C:\Windows\System32\schtasks.exe`
- **Alert Level:** 4 (below typical alerting threshold of Level 5+)
- **Channel:** `Microsoft-Windows-Sysmon/Operational`

### Impact
While the event is logged and visible in Wazuh, its low severity level means:
1. It may not appear in high-priority alert dashboards.
2. Analysts focusing on Level 5+ alerts might miss it.
3. Automated response rules triggered at Level 5+ won't activate.

### Root Cause
The default Wazuh rule for Sysmon Event ID 1 with `schtasks.exe` is configured at Level 4, assuming that task creation can be legitimate administrative activity.

## 📊 Evidence Summary

| Evidence Type | Event ID | Wazuh Detection | Alert Level |
|--------------|----------|-----------------|-------------|
| Brute Force (Failed) | 4625 | ✅ Alerted | Level 5+ |
| Successful Logon (RDP) | 4624 | ✅ Alerted | Level 5+ |
| Persistence (schtasks) | Sysmon 1 | ⚠️ Logged | Level 4 |

## 🚀 Recommendations

### Immediate Actions
1. **Isolate Host:** Disconnect 192.168.1.12 from the network.
2. **Reset Credentials:** Change password for `BruteTarget`.
3. **Remove Persistence:** `schtasks /delete /tn WinUpdater /f`

### SIEM Improvements
1. **Custom Alert Rule:** Create a Wazuh rule to elevate Sysmon Event ID 1 to Level 10 when `Image` contains `schtasks.exe` and `RuleName` contains `T1053.005`.
2. **Active Response:** Automatically block source IPs after 3 failed RDP attempts.
3. **Dashboard Tuning:** Add Sysmon T1053.005 to high-priority alert widgets.

### Example Custom Rule (for local_rules.xml):

```xml
<rule id="100001" level="10">
  <if_sid>81000</if_sid>
  <field name="win.eventdata.image">schtasks.exe</field>
  <field name="win.eventdata.ruleName">T1053.005</field>
  <description>Scheduled Task Creation Detected (Persistence Technique)</description>
</rule>
....

🧠 Lessons Learned
Tools Matter: Hydra's experimental RDP module failed; NetExec succeeded. Always have backup tools.
Level ≠ Visibility: An event can be logged but still missed if its severity level is too low for analyst workflows.
Sysmon is Powerful: Even without Windows Event ID 4698, Sysmon captured the persistence attempt with MITRE ATT&CK mapping.
Tuning is Critical: Default SIEM rules are not enough; custom rules are needed for specific attack techniques.
📸 Screenshots
01_account_prep: Account preparation
02_password_list: Password list for brute force
03_netexec_success: Successful brute force with NetExec
04_schtasks_success: Persistence mechanism created
05_evidence_files: Collected forensic evidence
06_pcap_size: Network capture file
07_wazuh_4625_failed: Failed logon attempts in Wazuh
08_wazuh_4624_success: Successful logon in Wazuh
09_local_event_4698_proof: Local Windows event proof
10_wazuh_level4_blind_spot: Persistence detected at Level 4
