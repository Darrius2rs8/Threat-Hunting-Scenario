# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [[Scenario Creation]https://github.com/Darrius2rs8/Threat-Hunting-Scenario/blob/main/threat-hunting-scenario-tor-event-creation.md

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer, did something that resulted in many tor related files being copied to the desktop and the create of a filed called “tor-shopping-list..txt” on the desktop. These events began at: 2025-07-09T15:59:55.3794363Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
|where initiatingprocessaccountname == “employee”
|where FileName contains "tor"
|where Timestamp >= datetime(2025-07-09T15:54:49.136327Z)
|order by Timestamp desc
|project Timestamp, DeviceName, ActionType,FileName,FolderPath,SHA256, account = InitiatingProcessAccountName


``

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any indication that the user “employee” actually opened the tor browser. There was evidence that they did open it at 2025-07-09T15:54:49.136327Z
There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == “threat-hunt-lab”
|where Filename has_any (“tor.exe”, “tor-browser.exe”)
|project Timestamp, DeviceName, AccountName, ActionType, Filename, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc

```


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known port numbers At 2025-07-15T01:43:03.7155769Z a device named "cyber-threatlab" had a program called "tor.exe" start running. It was launched by a user account named "hisislife".
This program connected to a remote IP address (65.21.1.225) using port 9001


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```


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

---

## Chronological Event Timeline 

###July 9, 2025 – 3:54:49 PM (UTC)
A user account named employee on the device threat-hunt-lab executed the Tor browser for the first time.


Process logs confirm that tor.exe or tor-browser.exe was launched.


This marks the initial evidence of Tor being opened by the user.


📅 July 9, 2025 – 3:59:55 PM (UTC)
The user employee ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from the Downloads folder.


The command included parameters indicating a silent installation, meaning it likely installed or extracted without user interaction.


This action resulted in multiple Tor-related files being written or copied to the user’s desktop.


📅 Shortly After 3:59:55 PM
A new file named tor-shopping-list..txt was created on the desktop.


The creation, and possibly modification, of this file was recorded during or shortly after the installation process.


The context suggests it may have been associated with the user’s activity involving the Tor browser.


🕒 (Post-Installation, Exact Times Not Fully Listed)
Multiple instances of tor.exe and firefox.exe (Tor’s browser) were observed spawning on the device.


These instances are consistent with the normal operation of the Tor Browser Bundle, where tor.exe handles network traffic and firefox.exe is the Tor front-end browser.


📅 July 15, 2025 – 1:43:03 AM (UTC)
On a separate device named cyber-threatlab, the file tor.exe was again executed—this time by a different user, hisislife.


The application successfully made an outbound connection to IP address 65.21.1.225 using port 9001, which is commonly used by Tor relays.


This indicates an active connection to the Tor network was successfully established.


---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

--- Threat-Hunting-Scenario
