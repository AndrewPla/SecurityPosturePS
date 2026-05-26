function Set-PSEventLogSize {
<#
.SYNOPSIS
    Sets event log maximum size (MB) for security-relevant logs.

.DESCRIPTION
    Uses wevtutil to set MaximumSizeInBytes for event logs.
    This helps retain enough events for investigation.

    Lab use: tune and validate quickly.
    Production use: set via centralized policy/control planes.

.PARAMETER LogName
    Name of the event log to resize.

.PARAMETER SizeMB
    New max size in MB. Minimum 50 MB.

.PARAMETER PassThru
    Returns Get-PSEventLogConfig output for the selected log after change.

.EXAMPLE
    Set-PSEventLogSize -LogName 'Microsoft-Windows-PowerShell/Operational' -SizeMB 256 -WhatIf

.EXAMPLE
    Set-PSEventLogSize -LogName 'Windows PowerShell' -SizeMB 128 -Confirm
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $LogName,

        [Parameter(Mandatory = $true)]
        [ValidateRange(50, 4096)]
        [int] $SizeMB,

        [Parameter()]
        [switch] $PassThru
    )

    $bytes = [int64]$SizeMB * 1MB

    if ($PSCmdlet.ShouldProcess($LogName, "Set max size to $SizeMB MB")) {
        & wevtutil.exe 'sl' $LogName "/ms:$bytes"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to update log size for '$LogName' (wevtutil exit code $LASTEXITCODE)."
        }

        if ($PassThru) {
            Get-PSEventLogConfig | Where-Object LogName -eq $LogName
        }
    }
}
