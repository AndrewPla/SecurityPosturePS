function Set-PSInvocationLogging {
<#
.SYNOPSIS
    Enables or disables Script Block Invocation Logging for lab machines.

.DESCRIPTION
    Sets the registry-backed invocation logging policy value:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging
    Value: EnableScriptBlockInvocationLogging (DWORD)

    This setting is most useful when Script Block Logging is also enabled.

.PARAMETER Enable
    Sets EnableScriptBlockInvocationLogging to 1.

.PARAMETER Disable
    Sets EnableScriptBlockInvocationLogging to 0.

.PARAMETER Backup
    Exports pre-change registry key values to JSON.

.PARAMETER BackupDirectory
    Folder for backup files.

.PARAMETER PassThru
    Returns Get-PSInvocationLogging output after change.

.PARAMETER Engine
    Which engine policy path to update:
    WindowsPowerShell, PowerShell7, or Both (default).
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

    $valueName = 'EnableScriptBlockInvocationLogging'
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
        $backupFile = Join-Path $BackupDirectory "Set-PSInvocationLogging-$Engine-$stamp.json"

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
        Get-PSInvocationLogging -Engine $Engine
    }
}
