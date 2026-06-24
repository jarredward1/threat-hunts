# Threat Hunt Investigation: Dunder Mifflin Unauthorized TOR usage
- [Scenario Creation]()

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Dunder Mifflin corporate headquarters in New York City recently flagged unusual encrypted traffic patterns originating from the Scranton branch network. Network logs revealed connections to known TOR entry nodes during business hours, prompting corporate to escalate the matter to the IT security team for a formal investigation. Branch manager Michael Scott, when contacted, stated he was "completely unaware" of any suspicious activity and suggested the traffic may have been related to his attempts to stream the latest episode of Threat Level Midnight, or possibly Dwight Schrute accessing beet farming forums he had been previously warned about. Corporate dismissed both explanations and noted that a separate anonymous tip had been submitted through the company's internal reporting system, believed to have been filed by Dwight himself in his capacity as self-appointed Assistant Regional Manager, suggesting that an employee in the Scranton office had been discussing ways to access restricted websites and purchase items through anonymous online channels during work hours. Toby Flenderson of the Scranton branch HR department was notified but his involvement was immediately overruled by corporate, who reminded all parties that Toby has no authority here and that this matter would be handled directly by the IT security team.

The device flagged in the network alert is `jarred-threat-h`, assigned to a Scranton branch employee operating under the account name `employee`. The goal of this threat hunt is to confirm whether unauthorized TOR usage occurred on this device, identify what the employee may have accessed or acquired through the TOR network, and determine the full scope of the incident so that appropriate action can be taken in accordance with Dunder Mifflin's acceptable use policy. All findings are to be reported directly to corporate, bypassing Michael Scott entirely, as previous incident escalations through the Scranton branch manager have resulted in a company-wide "Pretzel Day" being declared in lieu of disciplinary action.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

On June 23, 2026, the user "employee" on device `jarred-threat-h`, located on the Scranton branch floor of Dunder Mifflin, deliberately downloaded, silently installed, and actively used TOR Browser 15.0.16 (portable) to anonymize their internet traffic in violation of Dunder Mifflin's acceptable use policy, a document that Michael Scott has publicly referred to as "just a suggestion." Within approximately two minutes of installation, a fully operational TOR circuit was established with at least seven external guard relay nodes on ports 9001, 443, and 587, suggesting a level of technical sophistication not typically associated with the Scranton branch, immediately ruling out Kevin Malone. The session lasted over 21 minutes with up to 20 concurrent browser tabs observed, indicating sustained and intentional use of the TOR network during what should have been a regularly scheduled 2:00 PM branch meeting. Most critically, the user created a file named `tor-shopping-list.txt` on the Desktop at the conclusion of the session, strongly implying access to dark web marketplaces, the contents of which corporate has declined to speculate on but has noted are "deeply concerning and consistent with prior unexplained inventory discrepancies at the Scranton branch." Corporate should be notified immediately, and the findings should under no circumstances be delivered to Michael Scott via a musical number, a golden ticket promotion, or a Dundie Award ceremony.

---

## Response Taken

The device `jarred-threat-h` was immediately isolated from the network to prevent any further unauthorized data transmission or continued TOR activity. All relevant artifacts were preserved, including a full forensic image of the device, the `tor-shopping-list.txt` file from the Desktop, the TOR Browser profile directory at `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\`, and all associated logs from Microsoft Defender XDR. The user account `employee` was suspended pending the outcome of the investigation, and the incident was formally escalated to HR, legal counsel, and senior management in accordance with the organization's acceptable use and incident response policies. A broader review of network logs was also conducted to determine whether any sensitive data was exfiltrated through the TOR circuit during the active session window of 9:57 PM to 10:14 PM on June 23, 2026.

---
