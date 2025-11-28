<img width="256" height="256" alt="image" src="https://github.com/user-attachments/assets/737a2c13-6865-446b-9409-38d1eb267306" /> 


# Threat-Hunting-Malicious-Tech-Support
Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits. keywords discovered “desk,” “help,” “support,” and “tool.”

# 🔎 Threat Hunt Report: Support Session

Analyst: Fredrick Wilson

Date Completed: November 13th, 2025

Environment Investigated: gab-intern-vm

Timeframe: Early October 2025

## ℹ️ Scenario
A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this “support session”, and decide what was legitimate and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-10-09T13:13** | Flag 1   | Malicious file created (`Supporttool.ps1`)   | File dropped via PowerShell                             |
| **2025-10-09T12:34** | Flag 2   | Indicator of Security Posture Change        | DefenderTamperArtifact.lnk                            |
| **2025-10-09T12:50:39Z** | Flag 3   | User token impersonation attempt             |                                |
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

### 🚩 Flag 1 – Initial Execution Detection
**🎯 Objective**  
Detect the earliest anomalous execution that could represent an entry point.

**📌 Finding**  
`-ExecutionPolicy Bypass` (execution of `SupportTool.ps1`)

**🔍 Evidence**

| Field              | Value                                                                                              |
|--------------------|----------------------------------------------------------------------------------------------------|
| Host               | gab-intern-vm                                                                                      |
| Timestamp          | 2025-10-09T13:13:12.5263837Z                                                                       |
| Process            | powershell.exe                                                                                     |
| Parent Process     | explorer.exe                                                                                       |
| Command Line       | `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"` |

**💡 Why it matters**  
The observed PowerShell command explicitly uses `-ExecutionPolicy Bypass` and `-WindowStyle Hidden` to silently run an unsigned script from the user’s Downloads folder — the classic hallmark of user-initiated malicious execution in tech-support scams.

This single event marks the true initial foothold (MITRE ATT&CK **T1059.001** + **T1566.001**). Without it, none of the subsequent 14 flags occur. Detecting this pattern is one of the highest-signal, lowest-false-positive alerts available to defenders.

**🔧 KQL Query Used**
```kql
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```

**🖼️ Screenshot / Telemetry View**  
<img width="1513" height="483" alt="image" src="https://github.com/user-attachments/assets/71eae36c-65ec-4bf8-898d-618304e7fedd" />
*Figure 1: DeviceProcessEvents record showing the hidden PowerShell launch with -ExecutionPolicy Bypass*

**🛠️ Detection Recommendation**  
Alert on:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all("-ExecutionPolicy Bypass", "-WindowStyle Hidden")
   and FolderPath endswith @"Downloads\"
   or FolderPath in ("C:\\Temp\\", "C:\\Users\\Public\\", "C:\\Windows\\Temp\\")
```

---

### 🚩 Flag 2 – Defense Disabling
**🎯 Objective**  
Identify indicators that suggest to imply or simulate changing security posture.

**📌 Finding**  
`DefenderTamperArtifact.lnk`

**🔍 Evidence**

| Field            | Value                                                                                          |
|------------------|------------------------------------------------------------------------------------------------|
| Host             | gab-intern-vm                                                                                  |
| Timestamp        | 2025-10-09T12:34:59.1260624Z                                                                   |
| Process          | DefenderTamperArtifact.lnk → powershell.exe                                                    |
| Parent Process   | explorer.exe                                                                                   |
| Command Line     | `"C:\Users\g4bri3lintern\Downloads\DefenderTamperArtifact.lnk"`                                |

**💡 Why it matters**  
The file **DefenderTamperArtifact.lnk** is a Windows shortcut executed by the victim that launches hidden PowerShell commands to disable or weaken Microsoft Defender Antivirus (real-time protection, cloud-delivered protection, scan exclusions, etc.).  

.lnk files are heavily abused in real attacks because they can be disguised with any icon and silently run payloads without dropping an obvious .exe.  
In real incidents the name would be innocuous (e.g., “FixMyPC.lnk”), but the impact is identical: **MITRE ATT&CK T1562.001 – Impair Defenses**. Once Defender is neutralized, every subsequent payload (Flags 3–15) executes undetected.

**🔧 KQL Query Used**
```kql
DeviceFileEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where FileName contains "artifact" or FileName contains "tamper"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type
```

**🖼️ Screenshot**  
<img width="1498" height="206" alt="image" src="https://github.com/user-attachments/assets/3f5f4c3c-4220-47bf-94e7-3491d7ff7618" /> 
*Figure 2: User-initiated execution of the malicious shortcut that disables Defender*

**🛠️ Detection Recommendation**
```kql
DeviceProcessEvents
| where FileName endswith ".lnk"
| where ProcessCommandLine has_any("Set-MpPreference", "Add-MpPreference", "-DisableRealtimeMonitoring", "-Exclusion")
```
---

### 🚩 Flag 3 – Quick Data Probe
**🎯 Objective**  
Spot brief, opportunistic checks for available sensitive content.

**📌 Finding**  
`Get-Clipboard` executed silently from hidden PowerShell

**🔍 Evidence**

| Field            | Value                                                                                          |
|------------------|------------------------------------------------------------------------------------------------|
| Host             | gab-intern-vm                                                                                  |
| Timestamp        | 2025-10-09T12:50:39.955931Z                                                                    |
| Process          | powershell.exe                                                                                 |
| Parent Process   | powershell.exe (hidden)                                                                        |
| Command Line     | `powershell.exe -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`         |

**💡 Why it matters**  
This single-line PowerShell command silently attempts to steal whatever is currently on the victim’s clipboard (passwords, crypto addresses, documents, etc.). It is one of the fastest “easy wins” for attackers and appears extremely early in real tech-support scams and infostealer campaigns (MITRE ATT&CK **T1115 – Clipboard Data**). The `try/catch` and `Out-Null` ensure zero visible output even if the clipboard is empty.

**🔧 KQL Query Used**
```kql
DeviceProcessEvents
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```

**🖼️ Screenshot**  
<img width="1512" height="387" alt="image" src="https://github.com/user-attachments/assets/c8692b84-567f-4e77-9e1c-c769297fd16f" />



**🛠️ Detection Recommendation**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "Get-Clipboard"
| where InitiatingProcessCommandLine contains "-WindowStyle Hidden" or "-EncodedCommand"
```
---

### 🚩 Flag 4 – Host Context Recon
**🎯 Objective**  
Find activity that gathers basic host and user context to inform follow-up actions.

**📌 Finding**  
`qwinsta.exe` executed from hidden PowerShell

**🔍 Evidence**

| Field            | Value                                                                                          |
|------------------|------------------------------------------------------------------------------------------------|
| Host             | gab-intern-vm                                                                                  |
| Timestamp        | 2025-10-09T12:51:44.3425653Z                                                                   |
| Process          | qwinsta.exe                                                                                    |
| Parent Process   | powershell.exe (hidden)                                                                        |
| Command Line     | `qwinsta.exe`                                                                                  |

**💡 Why it matters**  
The attacker runs the legitimate Microsoft binary `qwinsta.exe` (Query User / Query WinStation) to silently enumerate current logon sessions. This single command instantly tells the attacker:
- The real username and session ID of the victim
- Whether anyone else (e.g., an admin) is already connected via RDP
- Which session is the active console and whether RDP is listening

In tech-support scams and ransomware attacks, this is a standard early reconnaissance step before enabling RDP, creating backdoors, or shadowing the victim’s session. Because `qwinsta.exe` is a signed system binary, it almost never triggers AV/EDR alerts (MITRE ATT&CK **T1033 – System Owner/User Discovery**).

**🔧 KQL Query Used**  
```
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```

**🖼️ Screenshot**  
<img width="1528" height="469" alt="image" src="https://github.com/user-attachments/assets/a19e818e-c493-4be2-9c22-62de6dbbfa0d" />
*Figure 4: qwinsta.exe executed from hidden PowerShell to reveal active user sessions*

**🛠️ Detection Recommendation**
```kql
DeviceProcessEvents
| where FileName in ("qwinsta.exe", "query.exe")
| where InitiatingProcessName == "powershell.exe"
   or InitiatingProcessCommandLine contains "-WindowStyle Hidden"
```
---

### 🚩 Flag 5 – Storage Surface Mapping
**🎯 Objective**  
Detection of local or network storage locations that might hold interesting data.

**📌 Finding**  
`wmic logicaldisk get name,freespace,size`

**🔍 Evidence**

| Field            | Value                                                                                          |
|------------------|------------------------------------------------------------------------------------------------|
| Host             | gab-intern-vm                                                                                  |
| Timestamp        | 2025-10-09T12:51:18.3848072Z                                                                   |
| Process          | cmd.exe                                                                                        |
| Parent Process   | powershell.exe (hidden session)                                                                |
| Command Line     | `"cmd.exe" /c wmic logicaldisk get name,freespace,size`                                        |

**💡 Why it matters**  
The attacker uses the built-in `wmic` command to silently enumerate all logical disks, their drive letters, total size, and free space. This extremely common reconnaissance step serves two critical purposes in real intrusions:

- Quickly identifies large drives or partitions that likely contain valuable data (Documents, Desktop, corporate shares, backups, databases, etc.)
- Reveals mapped network drives (often Z:\, S:\, etc.) that point to file servers — prime targets for ransomware encryption or data theft

Because `wmic.exe` is a signed Microsoft binary and the query itself looks perfectly legitimate, it rarely triggers alerts, yet it gives the attacker a full storage heatmap in milliseconds (MITRE ATT&CK **T1083 – File and Directory Discovery** combined with **T1135 – Network Share Discovery**).  
In tech-support scams and ransomware attacks, this exact command frequently appears minutes before mass encryption or exfiltration begins.

**🔧 KQL Query Used**
```kql
DeviceProcessEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "disk"
| project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine
```

**🖼️ Screenshot**  
<img width="1520" height="226" alt="image" src="https://github.com/user-attachments/assets/992f424c-b41c-487f-af40-3885ea3591c7" />
*Figure 5: Attacker mapping all local and network drives with size and free space*


**🛠️ Detection Recommendation**
```kql
DeviceProcessEvents
| where FileName == "wmic.exe"
| where ProcessCommandLine contains "logicaldisk" and ProcessCommandLine contains "get "
| where InitiatingProcessName == "powershell.exe" or InitiatingProcessCommandLine contains "-WindowStyle Hidden"
```
---

### 🚩 Flag 6 – Connectivity & Name Resolution Check  
**🎯 Objective**  
Identify brief probes that confirm whether the host can reach external infrastructure or resolve domain names.

**📌 Finding**  
`RuntimeBroker.exe` initiating unexpected outbound connectivity through PowerShell

**🔍 Evidence**

| Field            | Value                                                                 |
|------------------|-----------------------------------------------------------------------|
| Host             | gab-intern-vm                                                         |
| Timestamp        | 2025-10-09T12:55:05.7658713Z                                          |
| Process          | RuntimeBroker.exe                                                     |
| Parent Process   | Unknown / N/A (needs enrichment)                                      |
| Command Line     | `powershell.exe`                                                      |

**💡 Why it matters**  
`RuntimeBroker.exe` normally manages app permissions and should *rarely* be directly involved in outbound network calls. When it triggers PowerShell-based connectivity checks, it may indicate early-stage reconnaissance used to validate command-and-control reachability, test DNS resolution, or map egress paths. This behavior often precedes malware staging, payload downloads, or the establishment of persistence. Suspicious parent-child relationships involving PowerShell are strongly associated with MITRE ATT&CK **T1046 – Network Service Discovery** and **T1018 – Remote System Discovery**.

**🔧 KQL Query Used**

    DeviceNetworkEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName

**🖼️ Screenshot**  
<img width="1508" height="528" alt="image" src="https://github.com/user-attachments/assets/b37ee5f7-5e43-4c42-9a28-bf3ff4603055" />

**🛠️ Detection Recommendation**

    DeviceNetworkEvents
    | where InitiatingProcessFileName =~ "RuntimeBroker.exe"
    | where InitiatingProcessParentFileName =~ "powershell.exe"
    | project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName


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

---

🚩 **Flag 14 – Autorun Fallback Persistence**  
🎯 **Objective:** Spot lightweight autorun entries placed as backup persistence in user scope.  
📌 **Finding (answer):** RemoteAssistUpdater
🔍 **Evidence:**  
- **Host:**
- **Timestamp:** 
- **Process:** 
- **Command:**  
 
💡 **Why it matters:**
**KQL Query Used:**





---

🚩 **Flag 15 – Planted Narrative / Cover Artifact**  
🎯 **Objective:** Identify a narrative or explanatory artifact intended to justify the activity..  
📌 **Finding (answer):** * SupportChat_log.lnk 
🔍 **Evidence:**  
- **File:** 
- **Timestamp:** 2025-10-09T13:02:41.5698148Z
- **Process:** "NOTEPAD.EXE" C:\Users\g4bri3lintern\Downloads\SupportChat_log.txt  
- **Host:** · **Initiating:** 
💡 **Why it matters:** 
**KQL Query Used:**
```
DeviceFileEvents
| where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
| where DeviceName == "gab-intern-vm"
| where FileName contains "support"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type
```
<img width="1508" height="294" alt="image" src="https://github.com/user-attachments/assets/359e2ae3-d3e1-42a5-a84e-35e7d4d4bbad" />


### 🚩 Flag 7 – Interactive Session Discovery
**🎯 Objective**
Reveal interactive or active user sessions on the host.

**📌 Finding**
whoami /groups executed, SIDs enumerated: 2533274790397065

**🔍 Evidence**

| Field            | Value                               |
|------------------|-------------------------------------|
| Host             | gab-intern-vm                        |
| Timestamp        | 2025-10-09T12:52:14.3135459Z        |
| Process          | cmd.exe                              |
| Parent Process   | Unknown / N/A                        |
| Command Line     | cmd.exe /c whoami /groups            |

**💡 Why it matters**
Attackers enumerate user sessions and group memberships to understand privilege level and lateral movement potential, a core part of early reconnaissance (MITRE ATT&CK T1033 – Account Discovery).

**🔧 KQL Query Used**
    DeviceProcessEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | where ProcessCommandLine contains "who"
    | where ProcessCommandLine !contains "msedge"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId

**🛠️ Detection Recommendation**
    DeviceProcessEvents
    | where ProcessCommandLine contains "whoami" and ProcessCommandLine contains "/groups"
    | where InitiatingProcessFileName !contains "explorer.exe"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 8 – Runtime Application Inventory
**🎯 Objective**
Detect enumeration of running applications and services.

**📌 Finding**
tasklist.exe executed

**🔍 Evidence**

| Field            | Value                               |
|------------------|-------------------------------------|
| Host             | gab-intern-vm                        |
| Timestamp        | 2025-10-09T12:51:57.6866149Z        |
| Process          | cmd.exe                              |
| Command Line     | cmd.exe /c tasklist /v               |

**💡 Why it matters**
`tasklist /v` reveals all running processes, window titles, and session data. Attackers use this to find security tools, high-privilege processes, and high-value targets (MITRE ATT&CK T1057 – Process Discovery).

**🔧 KQL Query Used**
    DeviceProcessEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | where ProcessCommandLine contains "list"
    | where ProcessCommandLine !contains "msedge"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId

**🛠️ Detection Recommendation**
    DeviceProcessEvents
    | where ProcessCommandLine contains "tasklist"
    | where InitiatingProcessFileName !contains "explorer.exe"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 9 – Privilege Surface Check
**🎯 Objective**
Understand the actor’s current privilege level.

**📌 Finding**
Repeated execution of whoami /groups

**🔍 Evidence**

| Field            | Value                               |
|------------------|-------------------------------------|
| Host             | gab-intern-vm                        |
| Timestamp        | 2025-10-09T12:52:14.3135459Z        |
| Process          | cmd.exe                              |
| Command Line     | cmd.exe /c whoami /groups            |

**💡 Why it matters**
Privilege enumeration often occurs before escalation attempts. Understanding available group privileges informs what high-impact actions an attacker can take (MITRE ATT&CK T1069 – Permission Groups Discovery).

**🔧 KQL Query Used**
    DeviceProcessEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | where ProcessCommandLine contains "who"
    | where ProcessCommandLine !contains "msedge"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId
    | order by TimeGenerated asc

**🛠️ Detection Recommendation**
    DeviceProcessEvents
    | where ProcessCommandLine contains "whoami" and ProcessCommandLine contains "/groups"
    | where InitiatingProcessFileName !contains "explorer.exe"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 10 – Proof-of-Access & Egress Validation
**🎯 Objective**
Confirm outbound network reachability and test exfiltration value.

**📌 Finding**
Outbound traffic to www.msftconnecttest.com

**🔍 Evidence**

| Field            | Value                     |
|------------------|---------------------------|
| Host             | gab-intern-vm             |
| RemoteUrl        | www.msftconnecttest.com   |
| Sequence         | Not provided              |

**💡 Why it matters**
This URL is used for Windows connectivity checks (NCSI). Attackers leverage it to validate outbound access. Observed via unusual processes may indicate C2 egress testing (MITRE T1018 – Remote System Discovery).

**🔧 KQL Query Used**
    DeviceNetworkEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName
    | order by TimeGenerated asc

**🛠️ Detection Recommendation**
    DeviceNetworkEvents
    | where RemoteUrl contains "msftconnecttest"
    | project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 11 – Bundling / Staging Artifacts
**🎯 Objective**
Detect artifacts being staged for transfer.

**📌 Finding**
ReconArtifacts.zip

**🔍 Evidence**

| Field            | Value                     |
|------------------|---------------------------|
| Host             | gab-intern-vm             |
| Timestamp        | 2025-10-09T12:58:17.4364257Z |
| Initiating Process | powershell.exe          |

**💡 Why it matters**
Staging files into a single location can indicate exfiltration prep or malware packaging. Common MITRE technique: T1074 – Data Staged.

**🔧 KQL Query Used**
    DeviceFileEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where FileName contains "artifact" or FileName contains "tamper"
    | project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type

**🛠️ Detection Recommendation**
    DeviceFileEvents
    | where FileName contains "artifact" or FileName contains "zip"
    | project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 12 – Outbound Transfer Attempt (Simulated)
**🎯 Objective**
Identify attempts to move data off-host.

**📌 Finding**
Connection to 100.29.147.161

**🔍 Evidence**

| Field            | Value                     |
|------------------|---------------------------|
| Host             | gab-intern-vm             |
| Timestamp        | 2025-10-09T13:00:40.045127Z |
| Process          | powershell.exe            |

**💡 Why it matters**
Outbound network attempts to unknown IPs can indicate exfiltration or upload tests (MITRE T1041 – Exfiltration Over C2 Channel).

**🔧 KQL Query Used**
    DeviceNetworkEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemoteIPType, InitiatingProcessFileName, InitiatingProcessParentFileName
    | order by TimeGenerated asc

**🛠️ Detection Recommendation**
    DeviceNetworkEvents
    | where RemoteIP == "100.29.147.161"
    | project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteIP

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 13 – Scheduled Re-Execution Persistence
**🎯 Objective**
Detect creation of mechanisms to re-run tooling on logon.

**📌 Finding**
SupportToolUpdater scheduled task

**🔍 Evidence**

| Field            | Value                     |
|------------------|---------------------------|
| Command          | schtasks.exe /Create /SC ONLOGON /TN SupportToolUpdater ... |
| Host             | gab-intern-vm             |
| Timestamp        | 2025-10-09T13:01:28.7700443Z |

**💡 Why it matters**
Scheduled tasks can maintain persistence after logon. MITRE T1053 – Scheduled Task/Job.

**🔧 KQL Query Used**
    DeviceProcessEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | where ProcessCommandLine contains "sch"
    | where ProcessCommandLine !contains "msedge"
    | project TimeGenerated, DeviceName, ProcessCommandLine, FileName, InitiatingProcessCommandLine, InitiatingProcessUniqueId
    | order by TimeGenerated asc

**🛠️ Detection Recommendation**
    DeviceProcessEvents
    | where ProcessCommandLine contains "schtasks.exe"
    | project TimeGenerated, DeviceName, ProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 14 – Autorun Fallback Persistence
**🎯 Objective**
Spot lightweight autorun entries as backup persistence.

**📌 Finding**
RemoteAssistUpdater

**🔍 Evidence**

| Field            | Value                     |
|------------------|---------------------------|
| Host             | gab-intern-vm             |
| Timestamp        | (insert timestamp)        |
| Process          | (insert process)          |
| Command          | (insert command)          |

**💡 Why it matters**
Malware can add autorun entries to maintain persistence. MITRE T1547 – Boot or Logon Autostart Execution.

**🔧 KQL Query Used**
    DeviceRegistryEvents
    | where RegistryKey contains "Run" or RegistryKey contains "Startup"
    | where RegistryValueName contains "RemoteAssistUpdater"
    | project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData

**🛠️ Detection Recommendation**
    DeviceRegistryEvents
    | where RegistryValueName contains "RemoteAssistUpdater"
    | project TimeGenerated, DeviceName, RegistryKey, RegistryValueName

**🖼️ Screenshot**
🖼️ Insert screenshot here

---

### 🚩 Flag 15 – Planted Narrative / Cover Artifact
**🎯 Objective**
Identify a narrative or explanatory artifact intended to justify activity.

**📌 Finding**
SupportChat_log.lnk

**🔍 Evidence**

| Field            | Value                                             |
|------------------|--------------------------------------------------|
| File             | C:\Users\g4bri3lintern\Downloads\SupportChat_log.txt |
| Timestamp        | 2025-10-09T13:02:41.5698148Z                    |
| Process          | NOTEPAD.EXE                                      |
| Host             | gab-intern-vm                                    |

**💡 Why it matters**
Attackers sometimes create misleading artifacts to cover tracks or explain activity. MITRE T1604 – Masquerading / Covering Tracks.

**🔧 KQL Query Used**
    DeviceFileEvents
    | where TimeGenerated between (startofday(datetime(2025-10-09)) .. endofday(datetime(2025-10-09)))
    | where DeviceName == "gab-intern-vm"
    | where FileName contains "support"
    | project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, Type

**🛠️ Detection Recommendation**
    DeviceFileEvents
    | where FileName contains "support"
    | project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine

**🖼️ Screenshot**
🖼️ Insert screenshot here


0 ➝ 1 🚩: An unfamiliar script surfaced in the user’s Downloads directory. Was this SupportTool.ps1 executed under the guise of IT diagnostics?

1 ➝ 2 🚩: Initial execution often precedes an attempt to weaken defenses. Did the operator attempt to tamper with security tools to reduce visibility?

2 ➝ 3 🚩: With protections probed, the next step is quick data checks. Did they sample clipboard contents to see if sensitive material was immediately available?

3 ➝ 4 🚩: Attackers rarely stop with clipboard data. Did they expand into broader environmental reconnaissance to understand the host and user context?

4 ➝ 5 🚩: Recon of the system itself is followed by scoping available storage. Did the attacker enumerate drives and shares to see where data might live?

5 ➝ 6 🚩: After scoping storage, connectivity is key. Did they query network posture or DNS resolution to validate outbound capability?

6 ➝ 7 🚩: Once network posture is confirmed, live session data becomes valuable. Did they check active users or sessions that could be hijacked or monitored?

7 ➝ 8 🚩: Session checks alone aren’t enough — attackers want a full picture of the runtime. Did they enumerate processes to understand active applications and defenses?

8 ➝ 9 🚩: Process context often leads to privilege mapping. Did the operator query group memberships and privileges to understand access boundaries?

9 ➝ 10 🚩: With host and identity context in hand, attackers often validate egress and capture evidence. Was there an outbound connectivity check coupled with a screenshot of the user’s desktop?

10 ➝ 11 🚩: After recon and evidence collection, staging comes next. Did the operator bundle key artifacts into a compressed archive for easy movement?

11 ➝ 12 🚩: Staging rarely stops locally — exfiltration is tested soon after. Were outbound HTTP requests attempted to simulate upload of the bundle?

12 ➝ 13 🚩: Exfil attempts imply intent to return. Did the operator establish persistence through scheduled tasks to ensure continued execution?

13 ➝ 14 🚩: Attackers rarely trust a single persistence channel. Was a registry-based Run key added as a fallback mechanism to re-trigger the script?

14 ➝ 15 🚩: Persistence secured, the final step is narrative control. Did the attacker drop a text log resembling a helpdesk chat to possibly justify these suspicious activities? 
