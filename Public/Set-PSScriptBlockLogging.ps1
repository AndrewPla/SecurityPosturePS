function Set-PSScriptBlockLogging {
<#
.SYNOPSIS
    Enables or disables PowerShell Script Block Logging for lab machines.

.DESCRIPTION
    Sets the registry-backed Script Block Logging policy value:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging
    Value: EnableScriptBlockLogging (DWORD)

    Use this for lab/testing workflows. In production, prefer GPO/Intune.

.PARAMETER Enable
    Sets EnableScriptBlockLogging to 1.

.PARAMETER Disable
    Sets EnableScriptBlockLogging to 0.

.PARAMETER Backup
    Exports the pre-change registry key values to JSON under BackupDirectory.

.PARAMETER BackupDirectory
    Folder for backup files when -Backup is used.

.PARAMETER PassThru
    Returns Get-PSScriptBlockLogging output after applying the change.

.PARAMETER Engine
    Which engine policy path to update:
    WindowsPowerShell, PowerShell7, or Both (default).

.EXAMPLE
    Set-PSScriptBlockLogging -Enable -WhatIf

.EXAMPLE
    Set-PSScriptBlockLogging -Disable -Confirm
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Enable')]
    param(
        [Parameter(ParameterSetName = 'Enable', Mandatory = $true)]
        [switch] $Enable,

        [Parameter(ParameterSetName = 'Disable', Mandatory = $true)]
        [switch] $Disable,

        [Parameter()]
        [switch] $Backup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $BackupDirectory = "$env:ProgramData/SecurityPosturePS/Backups",

        [Parameter()]
        [ValidateSet('WindowsPowerShell', 'PowerShell7', 'Both')]
        [string] $Engine = 'Both',

        [Parameter()]
        [switch] $PassThru
    )

    $valueName = 'EnableScriptBlockLogging'
    $targetValue = if ($Enable) { 1 } else { 0 }
    $targets = switch ($Engine) {
        'WindowsPowerShell' { @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging') }
        'PowerShell7'       { @('HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging') }
        default             {
            @(
                'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
            )
        }
    }

    if ($Backup) {
        New-Item -Path $BackupDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupFile = Join-Path $BackupDirectory "Set-PSScriptBlockLogging-$Engine-$stamp.json"

        $snapshot = foreach ($path in $targets) {
            [PSCustomObject]@{
                RegistryPath = $path
                Current      = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            }
        }

        $snapshot | ConvertTo-Json -Depth 6 | Set-Content -Path $backupFile
        Write-Verbose "Backup written to $backupFile"
    }

    foreach ($regPath in $targets) {
        if ($PSCmdlet.ShouldProcess("$regPath::$valueName", "Set to $targetValue")) {
            New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $regPath -Name $valueName -Type DWord -Value $targetValue
        }
    }

    if ($PassThru) {
        Get-PSScriptBlockLogging -Engine $Engine
    }
}
