function Set-PSModuleLogging {
<#
.SYNOPSIS
    Enables or disables PowerShell Module Logging for lab machines.

.DESCRIPTION
    Sets the registry-backed Module Logging policy value:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    Value: EnableModuleLogging (DWORD)

    This command only controls the on/off switch. Fine-grained module include
    lists can be added in a later version.

.PARAMETER Enable
    Sets EnableModuleLogging to 1.

.PARAMETER Disable
    Sets EnableModuleLogging to 0.

.PARAMETER Backup
    Exports pre-change registry key values to JSON.

.PARAMETER BackupDirectory
    Folder for backup files.

.PARAMETER PassThru
    Returns Get-PSModuleLogging output after change.
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
        [switch] $PassThru
    )

    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $valueName = 'EnableModuleLogging'
    $targetValue = if ($Enable) { 1 } else { 0 }

    if ($Backup) {
        New-Item -Path $BackupDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $current = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupFile = Join-Path $BackupDirectory "Set-PSModuleLogging-$stamp.json"
        $current | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile
        Write-Verbose "Backup written to $backupFile"
    }

    if ($PSCmdlet.ShouldProcess("$regPath::$valueName", "Set to $targetValue")) {
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $regPath -Name $valueName -Type DWord -Value $targetValue

        if ($PassThru) {
            Get-PSModuleLogging
        }
    }
}
