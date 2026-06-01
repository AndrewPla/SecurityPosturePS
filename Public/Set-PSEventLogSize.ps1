function Set-PSEventLogSize {
<#
.SYNOPSIS
    Sets event log maximum size for security-relevant logs.

.DESCRIPTION
    Uses wevtutil.exe to set MaximumSizeInBytes for Windows event logs.

    This command can set one log at a time with -LogName and -SizeMB, or it can
    apply the SecurityPosturePS module baseline with -UseSecurityPostureBaseline.

    The baseline values are module defaults, not CISA/CIS/NIST/Microsoft/NSA
    mandated values. Log sizing is environment-dependent.

.PARAMETER LogName
    Name of the event log to resize.

.PARAMETER SizeMB
    New maximum size in MB.

.PARAMETER UseSecurityPostureBaseline
    Applies the SecurityPosturePS recommended baseline sizes:
      Security = 1024 MB
      Other monitored logs = 256 MB

.PARAMETER PassThru
    Returns Get-PSEventLogConfig output after applying changes.

.EXAMPLE
    Set-PSEventLogSize -LogName 'Microsoft-Windows-PowerShell/Operational' -SizeMB 256 -WhatIf

.EXAMPLE
    Set-PSEventLogSize -LogName 'Security' -SizeMB 1024 -Confirm

.EXAMPLE
    Set-PSEventLogSize -UseSecurityPostureBaseline -WhatIf

.EXAMPLE
    Set-PSEventLogSize -UseSecurityPostureBaseline -PassThru -Confirm
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'SingleLog')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'SingleLog')]
        [ValidateNotNullOrEmpty()]
        [string] $LogName,

        [Parameter(Mandatory = $true, ParameterSetName = 'SingleLog')]
        [ValidateRange(50, 4096)]
        [int] $SizeMB,

        [Parameter(Mandatory = $true, ParameterSetName = 'Baseline')]
        [switch] $UseSecurityPostureBaseline,

        [Parameter()]
        [switch] $PassThru
    )

    $baseline = [ordered]@{
        'Security'                                       = 1024
        'System'                                         = 256
        'Application'                                    = 256
        'Microsoft-Windows-PowerShell/Operational'       = 256
        'PowerShellCore/Operational'                     = 256
        'Windows PowerShell'                             = 256
        'Microsoft-Windows-AppLocker/MSI and Script'     = 256
        'Microsoft-Windows-Windows Defender/Operational' = 256
    }

    $targets = if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
        foreach ($entry in $baseline.GetEnumerator()) {
            [PSCustomObject]@{
                LogName = $entry.Key
                SizeMB  = $entry.Value
            }
        }
    }
    else {
        [PSCustomObject]@{
            LogName = $LogName
            SizeMB  = $SizeMB
        }
    }

    foreach ($target in $targets) {
        $logInfo = Get-WinEvent -ListLog $target.LogName -ErrorAction SilentlyContinue

        if (-not $logInfo) {
            Write-Warning "Skipping '$($target.LogName)' because the log was not found on this machine."
            continue
        }

        $bytes = [int64] $target.SizeMB * 1MB
        $action = "Set max size to $($target.SizeMB) MB"

        if ($PSCmdlet.ShouldProcess($target.LogName, $action)) {
            & wevtutil.exe 'sl' $target.LogName "/ms:$bytes"

            if ($LASTEXITCODE -ne 0) {
                throw "Failed to update log size for '$($target.LogName)' with wevtutil exit code $LASTEXITCODE."
            }
        }
    }

    if ($PassThru) {
        if ($PSCmdlet.ParameterSetName -eq 'Baseline') {
            Get-PSEventLogConfig
        }
        else {
            Get-PSEventLogConfig | Where-Object LogName -eq $LogName
        }
    }
}