<#
.SYNOPSIS
    Monitor incoming RDP connections (successful and/or failed) through Windows event log.

.DESCRIPTION
    This script checks Windows event logs to detect successful (ID 4624) or failed (ID 4625) RDP connections from remote accounts.
    It saves results in a CSV file for analysis.

.PARAMETER LogFile
    Generated CSV file path.

.PARAMETER SinceHours
    Number of hours to be analysed (default: 24).

.EXAMPLE
    .\Monitor-RDPConnections.ps1 -SinceHours 6 -LogFile "C:\YOUR\RESULTS\PATH\example.csv"
#>

param (
    [int]$SinceHours = 24,
    [string]$LogFile = ".\RDP_connections.csv"
)

# Checking Administrator rights
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Error "This script must be run as an administrator."
    exit 1
}

# Filtering by event ID: 4624 (successful), 4625 (failed)
$eventIDs = @(4624, 4625)

# Starting time
$startTime = (Get-Date).AddHours(-$SinceHours)

# Event extraction
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = $eventIDs
        StartTime = $startTime
    } -ErrorAction Stop

    $rdpEvents = foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $ipAddress = ($xml.Event.EventData.Data) | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
        $logonType = ($xml.Event.EventData.Data) | Where-Object {$_.Name -eq 'LogonType'}).'#text'
        $username = ($xml.Event.EventData.Data) | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
        $status = if ($event.Id -eq 4624) {"Successful"} else {"Failed"}

        # Type of connection 10 = RDP (RemoteInteractive)
        if ($logonType -eq "10" -and $ipAddress -and $username -notlike "*$") {
            [PSCustomObject]@{
            Date = $event.TimeCreated
            Status = $status
            Username = $username
            SourceIP = $ipAddress
            LogonType = $logonType
            EventID = $event.Id
            }
        }
    }

    if ($rdpEvents.Count -gt 0) {
        $rdpEvents | Export-Csv -Path $LogFile -NoTypeInformation -Encoding UTF8
        Write-Host "RDP report successfully generated: $LogFile"
    } else {
    Write-Host "No RDP connections detected in the past $SinceHours hours"
    }
}
catch {
    Write-Error "Error occurring during the analysis event: $_"
}
