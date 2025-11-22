# threat-hunting-malicious-tech-support
Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits. keywords discovered “desk,” “help,” “support,” and “tool.”

#  Threat Hunt Report: Papertrail

Analyst: Fredrick Wilson

Date Completed: November 13th, 2025

Environment Investigated: 

Timeframe: Early October 2025

## Scenario
A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-10-09T13:13:12.5263837Z** | Flag 1   | Malicious file created (`HRToolTracker.ps1`) | File dropped via PowerShell                             |
| **2025-07-18T02:43:07Z** | Flag 2   | Initial execution of staging script          | PowerShell running HR script                            |
| **2025-07-18T03:11:42Z** | Flag 3   | User token impersonation attempt             | Suspicious use of `runas`                               |
| **2025-07-18T04:19:53Z** | Flag 4   | Reconnaissance of accounts & groups          | `net user /domain`                                      |
| **2025-07-18T05:05:10Z** | Flag 5   | Privilege escalation via service abuse       | `sc.exe config`                                         |
| **2025-07-18T05:27:32Z** | Flag 6   | Credential dumping from `lsass.exe`          | 92 access attempts                                      |
| **2025-07-18T07:45:16Z** | Flag 7   | Local file staging                           | Promotion-related files                                 |
| **2025-07-18T09:22:55Z** | Flag 8   | Archive creation (`employee-data.zip`)       | HR data compressed                                      |
| **2025-07-18T14:12:40Z** | Flag 9   | Outbound ping to unusual domain              | `eo7j1sn715wk...pipedream.net`                          |
| **2025-07-18T15:28:44Z** | Flag 10  | Covert exfil attempt                         | Remote IP `52.54.13.125`                                |
| **2025-07-18T15:50:36Z** | Flag 11  | Persistence via registry run key             | `OnboardTracker.ps1`                                    |
| **2025-07-18T16:05:21Z** | Flag 12  | Personnel file repeatedly accessed           | `Carlos.Tanaka-Evaluation.lnk`                          |
| **2025-07-18T16:14:36Z** | Flag 13  | HR candidate list tampered                   | Modified `PromotionCandidates.csv` (SHA1: `65a5195...`) |
| **2025-07-18T17:38:55Z** | Flag 14  | Log clearing via `wevtutil`                  | Cleared Security, System, App logs                      |
| **2025-07-18T18:18:38Z** | Flag 15  | Anti-forensics exit prep                     | Dropped `EmptySysmonConfig.xml`                         |

---
### Starting Point – Identifying the Initial System

**Objective:**
Locate the machine that was compromised. Our clues that this was in early October gave us a place to begin searching. From there, we needed to locate any suspicious activity, and I began by searching for suspicious downloads. This led me to a firefox installer that was done silently and it set up some alarm bells.





**Host of Interest (Starting Point):** `gab-intern-vm`  
**Why:** Execution policy Bypass on powershell command from "Support"
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "tool" or ProcessCommandLine contains "support" or ProcessCommandLine contains "plan" or ProcessCommandLine contains "help"
| where ProcessCommandLine contains "Downloads" or ProcessCommandLine contains "download"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, InitiatingProcessFolderPath
```
<img width="1514" height="719" alt="image" src="https://github.com/user-attachments/assets/ff574b68-7e5f-4d83-a284-0e3aed77cf24" />



---

## Flag-by-Flag Findings

---

🚩 **Flag 1 – Initial Execution Detection**  
🎯 **Objective:** Detect the earliest anomalous execution that could represent an entry point. 
📌 **Finding (answer):** -ExecutionPolicy
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** 2025-10-09T13:13:12.5263837Z  
- **Process:** 
- **CommandLine:** `"powershell.exe" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"`   
💡 **Why it matters:**

**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```
<img width="1513" height="483" alt="image" src="https://github.com/user-attachments/assets/71eae36c-65ec-4bf8-898d-618304e7fedd" />

---


🚩 **Flag 2 – Defense Disabling**  
🎯 **Objective:** Identify indicators that suggest to imply or simulate changing security posture.  
📌 **Finding (answer):** DefenderTamperArtifact.lnk  
🔍 **Evidence:**  
- **Host:** gab-intern-vm
- **Timestamp:** 2025-10-09T12:34:59.1260624Z
- **Process:**  Explorer.EXE 
💡 **Why it matters:** `
**KQL Query Used:**
```
DeviceFileEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where FileName contains "artifact" or FileName contains "tamper"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type
```
<img width="1498" height="206" alt="image" src="https://github.com/user-attachments/assets/3f5f4c3c-4220-47bf-94e7-3491d7ff7618" />


---

🚩 **Flag 3 – Quick Data Probe**  
🎯 **Objective:** Spot brief, opportunistic checks for available sensitive content.  
📌 **Finding (answer):** "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"
🔍 **Evidence:**
- **Host:** gab-intern-vm
- **Timestamp:** 2025-10-09T12:50:39.955931Z
- **Process:**  
- **CommandLine:**  "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```
<img width="1512" height="387" alt="image" src="https://github.com/user-attachments/assets/c8692b84-567f-4e77-9e1c-c769297fd16f" />



---

🚩 **Flag 4 – Host Context Recon**  
🎯 **Objective:** Find activity that gathers basic host and user context to inform follow-up actions. 
📌 **Finding (answer):** 2025-10-09T12:51:44.3425653Z
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:**  2025-10-09T12:51:44.3425653Z
- **Process:** `"powershell.exe" qwinsta` → spawned **qwinsta.exe**  
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```
<img width="1528" height="469" alt="image" src="https://github.com/user-attachments/assets/a19e818e-c493-4be2-9c22-62de6dbbfa0d" />


---

🚩 **Flag 5 – Storage Surface Mapping**  
🎯 **Objective:** Detection of local or network storage locations that might hold interesting data. 
📌 **Finding (answer):** "cmd.exe" /c wmic logicaldisk get name,freespace,size 
🔍 **Evidence:**  
- **Host:**   
- **Timestamps:** 2025-10-09T12:51:18.3848072Z
- **Process:**  "cmd.exe" /c wmic logicaldisk get name,freespace,size 
- **CommandLine:** "cmd.exe" /c wmic logicaldisk get name,freespace,size   
💡 **Why it matters:**
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "disk"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```
<img width="1520" height="226" alt="image" src="https://github.com/user-attachments/assets/992f424c-b41c-487f-af40-3885ea3591c7" />


---

🚩 **Flag 6 – Connectivity & Name Resolution Check**  
🎯 **Objective:** Identify checks that validate network reachability and name resolution.  
📌 **Finding (answer):**  RuntimeBroker.exe
🔍 **Evidence:**  
- **Host:**   
- **Timestamps:** 2025-10-09T12:55:05.7658713Z
- **Process:**  
- **CommandLine:**  "powershell.exe" 
💡 **Why it matters:**
**KQL Query Used:**
```
DeviceNetworkEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName
```
<img width="1508" height="528" alt="image" src="https://github.com/user-attachments/assets/b37ee5f7-5e43-4c42-9a28-bf3ff4603055" />


---

🚩 **Flag 7 – Interactive Session Discovery**  
🎯 **Objective:** Reveal to detect interactive or active user sessions on the host.  
📌 **Finding (answer):  2533274790397065
🔍 **Evidence:**  
- **Host:** 
- **Timestamps:**  2025-10-09T12:52:14.3135459Z
- **Process:**   
- **CommandLines:**  "cmd.exe" /c whoami /groups
- **Initiating:** 
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "who"
| where ProcessCommandLine !contains "msedge"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId

```
<img width="1478" height="481" alt="image" src="https://github.com/user-attachments/assets/151b4586-33c8-4262-8e53-42aea244c743" />



---

🚩 **Flag 8 – Runtime Application Inventory**  
🎯 **Objective:** Detection of running applications and services to informance and opportunity. 
📌 **Finding (answer):** tasklist.exe  
🔍 **Evidence:**  
- **Host:** 
- **Timestamp:** 2025-10-09T12:51:57.6866149Z
- **Process:** "cmd.exe" /c tasklist /v 
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "list"
| where ProcessCommandLine !contains "msedge"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId
```
<img width="1495" height="134" alt="image" src="https://github.com/user-attachments/assets/56a12ed1-16b3-4c1d-adc6-1edf3b8ad89e" />


---

🚩 **Flag 9 – Privilege Surface Check**  
🎯 **Objective:** Detection to understand privileges available to the current actor.  
📌 **Finding (answer):** 2025-10-09T12:52:14.3135459Z
🔍 **Evidence:**  
- **Host:** 
- **Timestamp:** 2025-10-09T12:52:14.3135459Z
- **Process:** "cmd.exe" /c whoami /groups 
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "who"
| where ProcessCommandLine !contains "msedge"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="1506" height="431" alt="image" src="https://github.com/user-attachments/assets/57e54742-5a17-4128-a050-1ccb50954623" />


---

🚩 **Flag 10 – Proof-of-Access & Egress Validation**  
🎯 **Objective:** Find actions that both validate outbound reachability and try to capture host state for exfiltration value. 
📌 **Finding (answer):** www.msftconnecttest.com
🔍 **Evidence:**  
- **Host:**  
- **RemoteUrl:** www.msftconnecttest.com
- **Sequence:**  
💡 **Why it matters:**
**KQL Query Used:**
```
DeviceNetworkEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="1481" height="514" alt="image" src="https://github.com/user-attachments/assets/1c0f22ed-82d7-404f-8333-5cd4fdf304a6" />




---

🚩 **Flag 11 – Bundling / Staging Artifacts**  
🎯 **Objective:** Detection of artifacts into a single location or package for transfer. 
📌 **Finding (answer):** ReconArtifacts.zip
🔍 **Evidence:**  
- **Host:** 
- **Timestamp:**  2025-10-09T12:58:17.4364257Z
- **Initiating Process:** "powershell.exe" 
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceFileEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where FileName contains "artifact" or FileName contains "tamper"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type
```
<img width="1496" height="166" alt="image" src="https://github.com/user-attachments/assets/38cf4fd4-9006-4d01-a263-6dd209db05eb" />


---

🚩 **Flag 12 – Outbound Transfer Attempt (Simulated)**  
🎯 **Objective:** Identify to move data off-host or test upload capability.
📌 **Finding (answer):** 100.29.147.161
🔍 **Evidence:**  
- **Host:** 
- **Timestamp:** 2025-10-09T13:00:40.045127Z
- **Process:** "powershell.exe"
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceNetworkEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="1486" height="315" alt="image" src="https://github.com/user-attachments/assets/5ce1c7f2-bcc2-44ad-b4ec-0e094e5b76bf" />




---

🚩 **Flag 13 – Scheduled Re-Execution Persistence**  
🎯 **Objective:** Detection creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in. 
📌 **Finding (answer):**  SupportToolUpdater
🔍 **Evidence:**  
- **Command:**  "schtasks.exe" /Create /SC ONLOGON /TN SupportToolUpdater /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"" /RL LIMITED /F 
- **Host:**  
- **Timestamp:** 2025-10-09T13:01:28.7700443Z
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "sch"
| where ProcessCommandLine !contains "msedge"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId
| order by TimeGenerated asc
```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/user-attachments/assets/ce206008-93b6-48c1-a99c-2868db039031" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName == "PromotionCandidates.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessCommandLine

```
<img width="1497" height="330" alt="image" src="https://github.com/user-attachments/assets/a5f2c7e2-8561-4d29-9ca8-618f059d0f52" />



---

🚩 **Flag 14 – Audit Trail Disruption**  
🎯 **Objective:** Detect attempts to impair system forensics.  
📌 **Finding (answer):** **2025-07-19T05:38:55.6800388Z** (first log‑clear attempt)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Process:** `wevtutil.exe`  
- **Command:** `"wevtutil.exe" cl Security` (+ additional clears shortly after)  
- **SHA256:** `0b732d9ad576d1400db44edf3e750849ac481e9bbaa628a3914e5eef9b7181b0`  
💡 **Why it matters:** Clear Windows Event Logs → destroys historical telemetry; classic anti‑forensics.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="https://github.com/user-attachments/assets/af5db852-e1c5-4ff3-8919-aef0a6baa225" />



---

🚩 **Flag 15 – Final Cleanup and Exit Prep**  
🎯 **Objective:** Capture the combination of anti‑forensics actions signaling attacker exit.  
📌 **Finding (answer):** **2025-07-19T06:18:38.6841044Z**  
🔍 **Evidence:**  
- **File:** `EmptySysmonConfig.xml`  
- **Path:** `C:\Temp\EmptySysmonConfig.xml`  
- **Host:** nathan-iel-vm · **Initiating:** powershell.exe  
💡 **Why it matters:** Blinds Sysmon to suppress detection just prior to exit; ties off anti‑forensics chain.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName in ("ConsoleHost_history.txt","EmptySysmonConfig.xml","HRConfig.json")
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/user-attachments/assets/6334babb-6839-4281-b025-74346f5623e9" />


---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell) – Flags 1–5, 7–8  
- **Persistence:** T1547.001 (Run Keys) – Flag 11  
- **Discovery:** T1033/T1087 (whoami /all; group/user discovery) – Flags 1–3, 4  
- **Credential Access:** T1003.001 (LSASS dump) – Flag 7 (MiniDump via comsvcs.dll)  
- **Command & Control / Exfil:** T1071/T1041 – Flags 9–10 (pipedream.net, .net TLD, IP 52.54.13.125)  
- **Defense Evasion:** T1562.001/002 & T1070.001 – Flags 5–6 (Defender), 14–15 (log clear, Sysmon blind)

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
