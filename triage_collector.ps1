<#
.SYNOPSIS
    Rapid Incident Triage Collector - Ransomware Investigation Playbook

.DESCRIPTION
    Aggregates disk and process indicators associated with ransomware impact
    (encrypted file extensions, ransom note drops, and Volume Shadow Copy
    tampering via EID 4688) without altering file or event metadata.

    Intended for use in Phase 1 (Identification & Scoping) of the incident
    response playbook. Run with an account that has read access to the
    target simulation/investigation path and to the Security event log.

.NOTES
    Author:  [Your Name]
    Scope:   Read-only triage. Does not modify, quarantine, or delete files.
#>

param(
    [string]$TargetPath = "C:\Ransomware_Simulation",
    [string]$EncryptedExtensionFilter = "*.lockbit",
    [string]$RansomNoteFilter = "README.txt",
    [int]$MaxSecurityEvents = 500
)

Write-Host "`n[*] INITIATING RAPID INCIDENT TRIAGE COLLECTOR..." -ForegroundColor Cyan
Write-Host "[*] Target Path: $TargetPath" -ForegroundColor DarkGray

# 1. Scope Encrypted IoCs
$iocMatches = Get-ChildItem -Path $TargetPath -Recurse -Filter $EncryptedExtensionFilter -ErrorAction SilentlyContinue
Write-Host "`n[+] Encrypted Files Detected: $($iocMatches.Count)" -ForegroundColor Red
$iocMatches | Select-Object -First 3 Name, Length, LastWriteTime | Format-Table -AutoSize

# 2. Scope Ransom Note Drops
$notes = Get-ChildItem -Path $TargetPath -Recurse -Filter $RansomNoteFilter -ErrorAction SilentlyContinue
Write-Host "[+] Ransom Note Artifacts Located: $($notes.Count)" -ForegroundColor Yellow
$notes | Select-Object FullName, CreationTime | Format-Table -AutoSize

# 3. Telemetry Triage: VSS Tampering Checks (EID 4688)
$vssEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents $MaxSecurityEvents -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin' }
Write-Host "[+] Suspicious Process Events (VSS Tampering EID 4688): $($vssEvents.Count)" -ForegroundColor Magenta
$vssEvents | Select-Object -First 5 TimeCreated, Id | Format-Table -AutoSize

# Summary
Write-Host "`n[*] TRIAGE SUMMARY" -ForegroundColor Cyan
Write-Host "    Encrypted files : $($iocMatches.Count)"
Write-Host "    Ransom notes    : $($notes.Count)"
Write-Host "    VSS tamper hits : $($vssEvents.Count)"
Write-Host "`n[*] Triage collection complete. No source artifacts were modified." -ForegroundColor Green
