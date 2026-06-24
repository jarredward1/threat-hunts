# Threat Hunt Investigation: Dunder Mifflin Unauthorized TOR usage

>This document outlines the steps taken to simulate unauthorized TOR browser activity on a monitored endpoint, >generating the telemetry used in the main investigation report. This is the "red side" of the exercise — the >actions a threat actor (or insider) would take that the Imperial Security Division then hunts.

---

## Steps the Threat Actor Took to Create Logs and IoCs

1. **Download the TOR browser installer** from the official project site:
   `https://www.torproject.org/download/`

2. **Execute the silent installation** from the Downloads directory:
   ```
   tor-browser-windows-x86_64-portable-14.0.1.exe /S
   ```
   > The `/S` flag suppresses all installation prompts — a deliberate evasion technique that completes the installation in the background without visible windows.

3. **Open the TOR browser** from the desktop folder created during installation.

4. **Establish TOR connections** and browse sites through the anonymization network.
   Notable network activity generated:
   - Outbound connection to `176.198.159.33` on port `9001` (TOR relay)
   - Outbound connection to `194.164.169.85` on port `443` (HTTPS via TOR)
   - Local loopback connection to `127.0.0.1` on port `9150` (TOR SOCKS proxy)

5. **Create a file on the desktop** named `tor-shopping-list.txt` and populate it with content (simulating intent documentation).

6. The file artifacts — including the shopping list, browser shortcuts (`Tor-Browser.lnk`), and browser storage databases — remain on the desktop as forensic evidence.

---

## Tables Used to Detect IoCs

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceFileEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Detects TOR installer download, desktop file staging, and creation of `tor-shopping-list.txt` |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceProcessEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Detects silent installation execution and active TOR browser + `tor.exe` process spawning |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceNetworkEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Detects outbound TOR relay connections over ports 9001, 9030, 9040, 9050, 9051, 9150 |

---

## Related KQL Queries

```kql
// Detect TOR-related files — installer download and desktop staging
DeviceFileEvents
| where FileName startswith "tor"

// Detect the silent TOR installation execution
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Confirm TOR browser and tor.exe are present and running
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// Confirm TOR browser process execution
DeviceProcessEvents
| where ProcessCommandLine has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect active TOR relay network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// Detect the shopping list file creation or deletion
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## TOR Port Reference

| **Port** | **TOR Usage** |
|---|---|
| `9001` | Primary TOR relay (ORPort) — onion routing traffic |
| `9030` | TOR directory protocol |
| `9040` | TOR transparent proxy |
| `9050` | TOR SOCKS proxy (default) |
| `9051` | TOR control port |
| `9150` | TOR Browser SOCKS proxy (alternate, used by Tor Browser Bundle) |
| `443` | HTTPS traffic routed through TOR bridges |
| `80` | HTTP traffic routed through TOR bridges |

---

## Environment Details

| **Parameter** | **Value** |
|---|---|
| Target OS | Windows 10 (Azure Virtual Machine) |
| EDR Platform | Microsoft Defender for Endpoint |
| TOR Version | 14.0.1 (64-bit portable) |
| Endpoint Name | `threat-hunt-lab` |
| User Account | `employee` |
| Investigation Date | June 2026 |

---

## Created By:
- **Author Name**: Jarred Ward
- **Author Contact**: https://www.linkedin.com/in/jarredward1
- **Date**: June, 2026

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History

| **Version** | **Changes** | **Date** | **Modified By** |
|---|---|---|---|
| 1.0 | Initial draft | June 2026 | Jarred Ward |

