# Monitor-RDPConnections_PowerShell

## 🔍 PowerShell Script to Monitor RDP Login Attempts from Windows Security Logs

This PowerShell script scans the Windows Security Event Log to detect **Remote Desktop Protocol (RDP)** login attempts—both **successful** (`Event ID 4624`) and **failed** (`Event ID 4625`) — specifically filtered using **LogonType 10**, which identifies **RemoteInteractive logons**.

It outputs the results into a **CSV file**, enabling further analysis.

---

## 🎯 Project Purpose

This script was developed as part of my **self-training in PowerShell scripting for cybersecurity**.  
The aim was to:

- Understand how RDP events are logged in Windows Security logs
- Learn to parse XML-based event data with PowerShell
- Build a tool that helps **monitor suspicious remote login activity**

---

## 🧠 Key Concepts Learned

- Using `Get-WinEvent` with filter hash tables for performance
- Parsing event XML to extract structured data (`IpAddress`, `LogonType`, `TargetUserName`)
- Filtering logon events by type (e.g. `LogonType = 10` → RDP)
- Creating `PSCustomObject` records for CSV export
- Implementing secure error handling (`try/catch`)
- Validating admin privileges within the script

---

## ⚙️ Requirements

- Windows machine with PowerShell 5.1 or newer
- Administrator privileges (required to read Security logs)
- RDP connections must be logged (Security Audit Policy must include **Logon Events**)

---

## 🚀 Usage

### 🔁 Syntax

```powershell
.\Monitor-RDPConnections.ps1 [-SinceHours <int>] [-LogFile <string>]
```

### 📝 Parameters

| Parameter    | Description                                              | Default                 |
| ------------ | -------------------------------------------------------- | ----------------------- |
| `SinceHours` | How many past hours to analyze (e.g. `6` = last 6 hours) | `24`                    |
| `LogFile`    | Full path to export CSV with detected RDP attempts       | `.\RDP_connections.csv` |

### 📌 Examples

```powershell
# Analyze the last 24 hours of RDP login attempts and save to default CSV
.\Monitor-RDPConnections.ps1

# Analyze the last 6 hours and export results to a specific file
.\Monitor-RDPConnections.ps1 -SinceHours 6 -LogFile "C:\Logs\RDP_report.csv"
```

---

## 📂 Sample CSV Output

| Date                | Status  | Username      | SourceIP     | LogonType | EventID |
| ------------------- | ------- | ------------- | ------------ | --------- | ------- |
| 2025-07-09 08:14:33 | Success | jdoe          | 192.168.1.15 | 10        | 4624    |
| 2025-07-09 08:19:04 | Failure | administrator | 192.168.1.22 | 10        | 4625    |

---

## 🔒 Security & Best Practices

  - ✅ Filtered by LogonType 10 to ensure only RDP sessions are recorded

  - ✅ Proper error handling with try/catch

  - ✅ Does not modify system or registry settings

  - ✅ Validates admin privileges before execution

---

## 📄 License

MIT License
