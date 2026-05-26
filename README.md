# SecurityPosturePS

SecurityPosturePS is a PowerShell module for auditing Windows security posture with a focus on PowerShell logging, execution controls, AppLocker, Defender, WinRM, and event log health.

This project is designed for learning and lab validation first (v0.1).
For production, configure settings through Group Policy (GPO), Intune, or equivalent centralized management.

## What this module does today

- Audits key registry-backed security controls.
- Reports status in simple, pipeline-friendly output objects.
- Queries recent PowerShell and AppLocker events.
- Checks whether security-relevant event logs are enabled and large enough.

## Getting Started (Copy/Paste)

### 1) Import the module from source

Open PowerShell as Administrator and run:

```powershell
Set-Location /Users/andrewpla/repos/SecurityPosturePS
Import-Module ./SecurityPosturePS.psd1 -Force
Get-Command -Module SecurityPosturePS | Sort-Object Name
```

If import succeeds, you will see all `Get-*` functions exported by the module.

### 2) Run the full posture audit

```powershell
Get-PSSecurityPosture | Format-Table -AutoSize
```

Optional verbose mode:

```powershell
Get-PSSecurityPosture -Verbose | Format-Table -AutoSize
```

### 3) Save a report you can compare later

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = "$env:USERPROFILE/Desktop/SecurityPosture-$stamp.csv"
Get-PSSecurityPosture | Export-Csv -Path $out -NoTypeInformation
$out
```

### 4) Pull recent security events

PowerShell logging events:

```powershell
Get-PSRecentEvents -HoursBack 24 -MaxEvents 200 |
    Select-Object TimeCreated, EventId, Level, LogName, Message |
    Format-Table -Wrap
```

Windows PowerShell only:

```powershell
Get-PSRecentEvents -Engine WindowsPowerShell -EventId 4104 -MaxEvents 50 |
    Select-Object TimeCreated, Engine, EventId, LogName, Message |
    Format-Table -Wrap
```

PowerShell 7 only:

```powershell
Get-PSRecentEvents -Engine PowerShell7 -EventId 4104 -MaxEvents 50 |
    Select-Object TimeCreated, Engine, EventId, LogName, Message |
    Format-Table -Wrap
```

AppLocker script events:

```powershell
Get-AppLockerRecentEvents -HoursBack 24 -MaxEvents 200 |
    Select-Object TimeCreated, EventId, PolicyDecision, Message |
    Format-Table -Wrap
```

Event log configuration health:

```powershell
Get-PSEventLogConfig | Format-Table -AutoSize
```

Check registry-backed script block settings for both engines:

```powershell
Get-PSScriptBlockLogging -Engine Both | Format-Table CheckName, Engine, Status, CurrentValue -AutoSize
Get-PSInvocationLogging -Engine Both | Format-Table CheckName, Engine, Status, CurrentValue -AutoSize
```

## Quick "How bad is my setup?" view

Run this summary to spotlight risky states fast:

```powershell
$results = Get-PSSecurityPosture

$results |
    Where-Object {
        $_.Status -in @('Disabled', 'Not Configured', 'Too Small') -or
        $_.Status -match 'Bypass|Unrestricted'
    } |
    Select-Object CheckName, Status, CurrentValue, Notes |
    Format-Table -AutoSize -Wrap
```

This highlights weak or missing controls so you can prioritize fixes.

## Current Commands

### Orchestrator

- `Get-PSSecurityPosture`

### PowerShell logging checks

- `Get-PSScriptBlockLogging`
- `Get-PSInvocationLogging`
- `Get-PSModuleLogging`
- `Get-PSTranscription`
- `Get-PSProtectedEventLogging`

### Execution controls

- `Get-PSMachineExecutionPolicy`
- `Get-AppLockerScriptRules`

### Host defense

- `Get-WDRealTimeProtection`
- `Get-WinRMPolicy`

### Event logs

- `Get-PSEventLogConfig`
- `Get-PSRecentEvents`
- `Get-AppLockerRecentEvents`

### Lab configuration commands

- `Set-PSScriptBlockLogging`
- `Set-PSInvocationLogging`
- `Set-PSModuleLogging`
- `Set-PSTranscription`
- `Set-PSEventLogSize`

### Inventory

- `Get-PSVersionInfo`

## Lab Hardening: Set commands

The module now includes `Set-*` commands for lab machine hardening workflows.

### Safety model for all Set commands

All future `Set-*` commands should follow this pattern:

- `[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]`
- Include `-WhatIf` and `-Confirm` support (automatic via ShouldProcess)
- Include `-Backup` option to export current values before change
- Include `-PassThru` to return updated status object
- Include `-LabOnly` switch and warning text in help
- No reboot or service restart unless explicitly requested

### Included Set commands

1. `Set-PSScriptBlockLogging`
2. `Set-PSInvocationLogging`
3. `Set-PSModuleLogging`
4. `Set-PSTranscription`
5. `Set-PSEventLogSize`

These provide immediate logging and retention hardening for lab machines.

## Copy/Paste Lab Baseline

Preview all changes first:

```powershell
# 1) Baseline logging controls
Set-PSScriptBlockLogging -Enable -Engine Both -WhatIf
Set-PSInvocationLogging -Enable -Engine Both -WhatIf
Set-PSModuleLogging -Enable -WhatIf
Set-PSTranscription -Enable -OutputDirectory 'C:\ProgramData\PSTranscripts' -WhatIf

# 2) Increase log retention
Set-PSEventLogSize -LogName 'Microsoft-Windows-PowerShell/Operational' -SizeMB 256 -WhatIf
Set-PSEventLogSize -LogName 'Windows PowerShell' -SizeMB 128 -WhatIf
Set-PSEventLogSize -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -SizeMB 256 -WhatIf
Set-PSEventLogSize -LogName 'Microsoft-Windows-Windows Defender/Operational' -SizeMB 256 -WhatIf

# 3) Apply for real (remove -WhatIf once reviewed)
```

Apply for real and verify:

```powershell
Set-PSScriptBlockLogging -Enable -Engine Both -Confirm
Set-PSInvocationLogging -Enable -Engine Both -Confirm
Set-PSModuleLogging -Enable -Confirm
Set-PSTranscription -Enable -OutputDirectory 'C:\ProgramData\PSTranscripts' -Confirm

Set-PSEventLogSize -LogName 'Microsoft-Windows-PowerShell/Operational' -SizeMB 256 -Confirm
Set-PSEventLogSize -LogName 'Windows PowerShell' -SizeMB 128 -Confirm
Set-PSEventLogSize -LogName 'Microsoft-Windows-AppLocker/MSI and Script' -SizeMB 256 -Confirm
Set-PSEventLogSize -LogName 'Microsoft-Windows-Windows Defender/Operational' -SizeMB 256 -Confirm

Get-PSSecurityPosture | Format-Table -AutoSize
Get-PSEventLogConfig | Format-Table -AutoSize
```

## Production guidance

Use these functions to learn and validate behavior in a lab.
For production environments, enforce settings with:

- Group Policy (recommended for domain-joined endpoints)
- Intune / MDM CSPs
- Configuration management tooling (DSC, Ansible, etc.)

This keeps policy consistent and prevents drift.

## Troubleshooting

### No events returned

- Verify policy is enabled with `Get-PSScriptBlockLogging`, `Get-PSModuleLogging`, and `Get-PSTranscription`.
- Verify log exists and is enabled via `Get-PSEventLogConfig`.
- Generate test activity, then query again.

### AppLocker log empty

- AppLocker script rules may not be configured.
- Application Identity service (`AppIDSvc`) may not be running.

### Access denied

- Run PowerShell as Administrator.

## Version

- Module version: `0.1.0`
- PowerShell minimum: `5.1`

## Updating this README

When module behavior changes, update this file in the same PR.
At minimum, keep these sections current:

- `Getting Started (Copy/Paste)`
- `Current Commands`
- `Lab Hardening: what to set next`
- `Copy/Paste Lab Baseline (planned once Set commands exist)`
