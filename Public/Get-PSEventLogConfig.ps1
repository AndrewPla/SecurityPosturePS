function Get-PSEventLogConfig {
<#
.SYNOPSIS
    Audits the configuration of PowerShell-related Windows event logs.

.DESCRIPTION
    Enabling Script Block Logging or Module Logging is only half the battle.
    If the event log that receives those events is too small, disabled, or set
    to overwrite aggressively, critical forensic data will be lost before
    anyone can investigate.

    This function checks four security-relevant event logs and evaluates two
    things for each:
      1. Is the log enabled?
      2. Is the configured maximum size adequate?

    LOGS CHECKED
      Microsoft-Windows-PowerShell/Operational
        The primary PowerShell security log. Receives Script Block Logging
        (Event 4104), Module Logging (Event 4103), and Transcription lifecycle
        events (4105/4106). Default max size is only 15 MB -- far too small
        for any environment under active use.

      Windows PowerShell (classic)
        The legacy PowerShell event log. Still receives engine lifecycle events
        and command history on Windows PowerShell 5.1.

      Microsoft-Windows-AppLocker/MSI and Script
        AppLocker script enforcement events (allowed, audited, blocked).
        Only populated when AppLocker script rules are configured.

      Microsoft-Windows-Windows Defender/Operational
        Windows Defender threat detection, remediation, and scan events.

    SIZE THRESHOLDS
    This function flags logs under 50 MB as 'Too Small'. This is a conservative
    minimum. The NSA and CISA recommend 1 GB or more for high-value security
    logs, and Microsoft's own guidance for PowerShell/Operational on servers
    suggests at least 100 MB. The 15 MB default should always be increased.

    HOW TO CONFIGURE LOG SIZES IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Event Log Service
         > <Log Name>
         > Maximum Log Size (KB)  ->  set to at least 102400 (100 MB)

    Or via wevtutil on a single machine (for testing only -- not for production):
        wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:104857600

    This function is read-only and shows you the current registry-backed
    configuration. It is a learning and auditing tool, not a remediation tool.

    WHAT "GOOD" LOOKS LIKE
    Status = 'OK'  for all four logs

.EXAMPLE
    PS> Get-PSEventLogConfig

    Returns the configuration status of all four monitored event logs.

.EXAMPLE
    PS> Get-PSEventLogConfig | Where-Object Status -ne 'OK' |
            Select-Object LogName, Status, MaxSizeMB, Notes

    Shows only misconfigured logs with the reason and Notes explanation.

.EXAMPLE
    PS> Get-PSEventLogConfig | Format-Table LogName, IsEnabled, MaxSizeMB, RecordCount, Status -AutoSize

    Compact table view of all log configuration properties.

.OUTPUTS
    [PSCustomObject] One object per monitored log with properties:
        ComputerName  - Machine audited
        CheckName     - 'Event Log Config: <LogName>'
        LogName       - Full Windows event log name
        IsEnabled     - Boolean: whether the log is currently enabled
        MaxSizeMB     - Configured maximum log size in megabytes
        RecordCount   - Current number of events in the log
        LogMode       - Circular | AutoBackup | Retain
        RegistryPath  - Registry key path that backs this log's config
        Status        - OK | Too Small | Disabled | Not Found
        Notes         - Plain-English explanation of the finding
        Reference     - Official documentation URL

.NOTES
    Module      : SecurityPosturePS v0.1.0
    Size floor  : 50 MB flagged as 'Too Small' -- CISA recommends >= 1 GB
    Registry    : HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<encoded-name>
                  Classic logs: HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\<name>

.LINK
    https://learn.microsoft.com/en-us/windows/win32/wes/eventmanifestschema-channeltype-complextype

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

.LINK
    https://www.cisa.gov/resources-tools/resources/logging-made-easy
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName    = $env:COMPUTERNAME
        $minSizeBytes    = 50MB   # Conservative floor; flag anything below this.
        $winevtRegBase   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels'
        $classicLogBase  = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'

        # Each entry: LogName, a short Purpose label, and its Reference URL.
        $targets = @(
            [PSCustomObject]@{
                LogName   = 'Microsoft-Windows-PowerShell/Operational'
                Purpose   = 'Primary PowerShell security log; receives Script Block (4104), Module Logging (4103), and Transcription (4105/4106) events'
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName   = 'PowerShellCore/Operational'
                Purpose   = 'PowerShell 7+ security log; receives script block and related engine events for pwsh sessions'
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName   = 'Windows PowerShell'
                Purpose   = 'Classic PowerShell log; receives engine lifecycle and legacy command history events'
                Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
            [PSCustomObject]@{
                LogName   = 'Microsoft-Windows-AppLocker/MSI and Script'
                Purpose   = 'AppLocker script policy events: 8005 = allowed, 8006 = audit (would-have-blocked), 8007 = blocked'
                Reference = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview'
            }
            [PSCustomObject]@{
                LogName   = 'Microsoft-Windows-Windows Defender/Operational'
                Purpose   = 'Windows Defender threat detection, remediation, and scan result events'
                Reference = 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus'
            }
        )
    }

    process {
        foreach ($target in $targets) {

            Write-Verbose "[$computerName] Checking event log config: $($target.LogName)"

            # Get-WinEvent -ListLog returns the live config including IsEnabled,
            # MaximumSizeInBytes, RecordCount, and LogMode.
            $logInfo = Get-WinEvent -ListLog $target.LogName -ErrorAction SilentlyContinue

            if (-not $logInfo) {
                # Build the registry path even for not-found logs so the output
                # is still useful (shows what path to investigate).
                $encodedName = $target.LogName -replace '/', '%4'
                $regPath     = if ($target.LogName -notmatch '/') {
                    "$classicLogBase\$($target.LogName)"
                } else {
                    "$winevtRegBase\$encodedName"
                }

                [PSCustomObject]@{
                    ComputerName = $computerName
                    CheckName    = "Event Log Config: $($target.LogName)"
                    LogName      = $target.LogName
                    IsEnabled    = $null
                    MaxSizeMB    = $null
                    RecordCount  = $null
                    LogMode      = $null
                    RegistryPath = $regPath
                    Status       = 'Not Found'
                    Notes        = "Log not found on this machine. $($target.Purpose)"
                    Reference    = $target.Reference
                }
                continue
            }

            $maxSizeMB  = [Math]::Round($logInfo.MaximumSizeInBytes / 1MB, 1)
            $encodedName = $target.LogName -replace '/', '%4'
            $regPath     = if ($target.LogName -notmatch '/') {
                "$classicLogBase\$($target.LogName)"
            } else {
                "$winevtRegBase\$encodedName"
            }

            $status = if (-not $logInfo.IsEnabled) {
                'Disabled'
            } elseif ($logInfo.MaximumSizeInBytes -lt $minSizeBytes) {
                'Too Small'
            } else {
                'OK'
            }

            $notes = switch ($status) {
                'Disabled'  { "Log is disabled; no events will be written. $($target.Purpose)" }
                'Too Small' { "Max size is $maxSizeMB MB (below 50 MB threshold); events will be overwritten too quickly for forensic retention. CISA recommends >= 1 GB. $($target.Purpose)" }
                'OK'        { "$($target.Purpose)" }
            }

            Write-Verbose "[$computerName] $($target.LogName) => $status (MaxSize: ${maxSizeMB} MB, Records: $($logInfo.RecordCount))"

            [PSCustomObject]@{
                ComputerName = $computerName
                CheckName    = "Event Log Config: $($target.LogName)"
                LogName      = $target.LogName
                IsEnabled    = $logInfo.IsEnabled
                MaxSizeMB    = $maxSizeMB
                RecordCount  = $logInfo.RecordCount
                LogMode      = $logInfo.LogMode.ToString()
                RegistryPath = $regPath
                Status       = $status
                Notes        = $notes
                Reference    = $target.Reference
            }
        }
    }
}
