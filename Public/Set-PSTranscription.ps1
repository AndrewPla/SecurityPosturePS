function Set-PSTranscription {
<#
.SYNOPSIS
    Enables or disables PowerShell Transcription for lab machines.

.DESCRIPTION
    Sets transcription policy values under:
    HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription

    Values written:
    - EnableTranscripting (DWORD)
    - OutputDirectory (String, when provided)

    Use this for labs and validation. In production, prefer GPO/Intune.

.PARAMETER Enable
    Enables transcription (EnableTranscripting = 1).

.PARAMETER Disable
    Disables transcription (EnableTranscripting = 0).

.PARAMETER OutputDirectory
    Transcript output directory to set when enabling.

.PARAMETER Backup
    Exports pre-change registry key values to JSON.

.PARAMETER BackupDirectory
    Folder for backup files.

.PARAMETER PassThru
    Returns Get-PSTranscription output after change.
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Enable')]
    param(
        [Parameter(ParameterSetName = 'Enable', Mandatory = $true)]
        [switch] $Enable,

        [Parameter(ParameterSetName = 'Disable', Mandatory = $true)]
        [switch] $Disable,

        [Parameter(ParameterSetName = 'Enable')]
        [ValidateNotNullOrEmpty()]
        [string] $OutputDirectory,

        [Parameter()]
        [switch] $Backup,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string] $BackupDirectory = "$env:ProgramData/SecurityPosturePS/Backups",

        [Parameter()]
        [switch] $PassThru
    )

    $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'

    if ($Backup) {
        New-Item -Path $BackupDirectory -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        $current = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupFile = Join-Path $BackupDirectory "Set-PSTranscription-$stamp.json"
        $current | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile
        Write-Verbose "Backup written to $backupFile"
    }

    $targetValue = if ($Enable) { 1 } else { 0 }

    if ($PSCmdlet.ShouldProcess($regPath, "Set EnableTranscripting to $targetValue")) {
        New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $regPath -Name 'EnableTranscripting' -Type DWord -Value $targetValue

        if ($Enable -and $OutputDirectory) {
            Set-ItemProperty -Path $regPath -Name 'OutputDirectory' -Type String -Value $OutputDirectory
        }

        if ($PassThru) {
            Get-PSTranscription
        }
    }
}
