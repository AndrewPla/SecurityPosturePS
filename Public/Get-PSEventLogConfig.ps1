function Get-PSEventLogConfig {
<#
.SYNOPSIS
    Audits the configuration of security-relevant Windows event logs.

.DESCRIPTION
    Enabling PowerShell, AppLocker, Defender, or Security auditing is only useful
    if the event logs that receive those events are enabled and large enough to
    retain useful local evidence.

    This function checks whether important Windows event logs exist, whether they
    are enabled, and whether their configured maximum size meets the
    SecurityPosturePS module baseline.

    IMPORTANT
    SecurityPosturePS does not claim that these size baselines are mandated by
    CISA, CIS, NIST, Microsoft, or NSA. Log sizing is environment-dependent.
    Size logs based on event volume, forwarding frequency, retention needs, and
    incident response requirements.

    The reference used here is NIST SP 800-92, Guide to Computer Security Log
    Management. It provides general guidance for building and maintaining log
    management practices, but it does not prescribe a single Windows event log
    size.

    LOGS CHECKED
      Security
        Windows Security audit log. Contains high-value audit events such as
        logons, account changes, privilege use, policy changes, process creation
        when enabled, and Event ID 1102 when the Security audit log is cleared.

      System
        Windows system log. Includes Event ID 104 when a Windows event log is
        cleared.

      Application
        Windows application log. Useful for application and service-level events.

      Microsoft-Windows-PowerShell/Operational
        Primary Windows PowerShell operational log. Receives Script Block Logging
        4104, Module Logging 4103, and invocation events 4105/4106 when enabled.

      PowerShellCore/Operational
        PowerShell 7+ operational log for pwsh sessions.

      Windows PowerShell
        Classic PowerShell event log for Windows PowerShell 5.1 engine events.

      Microsoft-Windows-AppLocker/MSI and Script
        AppLocker script policy events.

      Microsoft-Windows-Windows Defender/Operational
        Microsoft Defender threat detection, remediation, and scan events.

    HOW TO CONFIGURE LOG SIZES IN PRODUCTION
    Prefer Group Policy, Intune, MDM, or your configuration management platform.

    Group Policy path:
        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Event Log Service
         > <Log Name>
         > Maximum Log Size (KB)

    For lab testing on one machine, you can use wevtutil:
        wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456

.EXAMPLE
    Get-PSEventLogConfig

.EXAMPLE
    Get-PSEventLogConfig | Format-Table LogName, Status, MaxSizeMB, RecommendedMinimumSizeMB -AutoSize

.EXAMPLE
    Get-PSEventLogConfig | Where-Object Status -ne 'OK'

.OUTPUTS
    [PSCustomObject]

.LINK
    https://csrc.nist.gov/pubs/sp/800/92/final

.LINK
    https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channeltype-complextype

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        $winevtRegBase = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'
        $classicLogBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'
        $nistReference = 'https://csrc.nist.gov/pubs/sp/800/92/final'

        $targets = @(
            [PSCustomObject]@{
                LogName = 'Security'
                Purpose = 'Windows Security audit log. Contains high-value audit events such as logons, account changes, privilege use, policy changes, and Event ID 1102 when the Security audit log is cleared.'
                RecommendedMinimumSizeMB = 1024
                Reference = $nistReference
            }
            [PSCustomObject]@{
                LogName = 'System'
                Purpose = 'Windows system log. Includes Event ID 104 when a Windows event log is cleared.'
                RecommendedMinimumSizeMB = 256
                Reference = $nistReference
            }
            [PSCustomObject]@{
                LogName = 'Application'
                Purpose = 'Windows application log. Useful for application and service-level events that can support troubleshooting and incident response.'
                RecommendedMinimumSizeMB = 256
                Reference = $nistReference
            }
            [PSCustomObject]@{
                LogName = 'Microsoft-Windows-PowerShell/Operational'
                Purpose = 'Primary Windows PowerShell operational log. Receives Script Block Logging 4104, Module Logging 4103, and invocation events 4105/4106 when enabled.'
                RecommendedMinimumSizeMB = 256
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName = 'PowerShellCore/Operational'
                Purpose = 'PowerShell 7+ operational log for pwsh sessions.'
                RecommendedMinimumSizeMB = 256
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName = 'Windows PowerShell'
                Purpose = 'Classic PowerShell log for Windows PowerShell 5.1 engine and lifecycle events.'
                RecommendedMinimumSizeMB = 256
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
                Purpose = 'AppLocker script policy events such as allowed, audited, and blocked script execution.'
                RecommendedMinimumSizeMB = 256
                Reference = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview'
            }
            [PSCustomObject]@{
                LogName = 'Microsoft-Windows-Windows Defender/Operational'
                Purpose = 'Microsoft Defender threat detection, remediation, and scan result events.'
                RecommendedMinimumSizeMB = 256
                Reference = 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
            }
        )
    }

    process {
        foreach ($target in $targets) {
            Write-Verbose "[$computerName] Checking event log config: $($target.LogName)"

            $logInfo = Get-WinEvent -ListLog $target.LogName -ErrorAction SilentlyContinue
            $encodedName = $target.LogName -replace '/', '%4'

            if ($target.LogName -notmatch '/') {
                $regPath = "$classicLogBase\$($target.LogName)"
            }
            else {
                $regPath = "$winevtRegBase\$encodedName"
            }

            if (-not $logInfo) {
                [PSCustomObject]@{
                    ComputerName = $computerName
                    CheckName = "Event Log Config: $($target.LogName)"
                    LogName = $target.LogName
                    IsEnabled = $null
                    MaxSizeMB = $null
                    RecommendedMinimumSizeMB = $target.RecommendedMinimumSizeMB
                    RecordCount = $null
                    LogMode = $null
                    RegistryPath = $regPath
                    Status = 'Not Found'
                    Notes = "Log not found on this machine. $($target.Purpose)"
                    Reference = $target.Reference
                }

                continue
            }

            $maxSizeMB = [Math]::Round($logInfo.MaximumSizeInBytes / 1MB, 1)
            $recommendedMinimumSizeMB = $target.RecommendedMinimumSizeMB

            if (-not $logInfo.IsEnabled) {
                $status = 'Disabled'
            }
            elseif ($maxSizeMB -lt $recommendedMinimumSizeMB) {
                $status = 'Too Small'
            }
            else {
                $status = 'OK'
            }

            switch ($status) {
                'Disabled' {
                    $notes = "Log is disabled. No events will be written to this log. $($target.Purpose)"
                }
                'Too Small' {
                    $notes = "Maximum size is $maxSizeMB MB, which is below the SecurityPosturePS baseline of $recommendedMinimumSizeMB MB. This is not a CISA-mandated value. Log size should be tuned for event volume, forwarding frequency, retention needs, and incident response requirements. $($target.Purpose)"
                }
                default {
                    $notes = "Maximum size is $maxSizeMB MB, which meets the SecurityPosturePS baseline of $recommendedMinimumSizeMB MB. $($target.Purpose)"
                }
            }

            Write-Verbose "[$computerName] $($target.LogName) => $status (MaxSize: $maxSizeMB MB, Recommended: $recommendedMinimumSizeMB MB, Records: $($logInfo.RecordCount))"

            [PSCustomObject]@{
                ComputerName = $computerName
                CheckName = "Event Log Config: $($target.LogName)"
                LogName = $target.LogName
                IsEnabled = $logInfo.IsEnabled
                MaxSizeMB = $maxSizeMB
                RecommendedMinimumSizeMB = $recommendedMinimumSizeMB
                RecordCount = $logInfo.RecordCount
                LogMode = $logInfo.LogMode.ToString()
                RegistryPath = $regPath
                Status = $status
                Notes = $notes
                Reference = $target.Reference
            }
        }
    }
}
