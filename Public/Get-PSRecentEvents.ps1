function Get-PSRecentEvents {
<#
.SYNOPSIS
    Queries recent PowerShell security events from the Windows event log.

.DESCRIPTION
    Get-PSRecentEvents reads the Microsoft-Windows-PowerShell/Operational log
    and returns recent events by the IDs most relevant to security monitoring.
    This is the event log that Script Block Logging, Module Logging, and
    Transcription lifecycle events are written to.

    POWERSHELL EVENT IDS QUERIED BY DEFAULT
      4103  Module Logging -- pipeline execution details for a module command
      4104  Script Block Logging -- full content of an executed script block
      4105  Transcription started -- a new PS transcript file was opened
      4106  Transcription stopped -- a PS transcript file was closed

    Event 4104 is the most security-relevant: it contains the full decoded
    script text, including any code that was obfuscated at the network or disk
    level. Attackers who encode payloads with Base64 or use Invoke-Expression
    will still appear in 4104 events.

    BEFORE USING THIS FUNCTION
    This function only returns events if the corresponding logging policies
    are enabled. If you get no results, check:
        Get-PSScriptBlockLogging   -- must be Enabled for 4104 events
        Get-PSModuleLogging        -- must be Enabled for 4103 events
        Get-PSTranscription        -- must be Enabled for 4105/4106 events
        Get-PSEventLogConfig       -- confirms the log is large enough to retain events

    USE CASE: VERIFY LOGGING IS WORKING
    The most common use of this function during a security baseline review is
    to confirm that logging is actually producing events after you have verified
    the registry settings are configured correctly. If policies are Enabled but
    this function returns nothing, something in the logging chain is broken.

    This function is read-only.

.PARAMETER MaxEvents
    Maximum number of events to return. Default: 50.
    Increase this for broader historical searches.

.PARAMETER HoursBack
    How many hours back to search. Default: 24 (last 24 hours).
    Set to 0 to return all available events up to -MaxEvents.

.PARAMETER EventId
    One or more specific event IDs to filter on.
    Default: 4103, 4104, 4105, 4106 (all PS security event IDs).

.PARAMETER Engine
    Which PowerShell engine log(s) to query.
    WindowsPowerShell = Microsoft-Windows-PowerShell/Operational
    PowerShell7       = PowerShellCore/Operational
    Both              = Query both logs (default)

.EXAMPLE
    PS> Get-PSRecentEvents

    Returns up to 50 PowerShell security events from the last 24 hours.

.EXAMPLE
    PS> Get-PSRecentEvents -EventId 4104 -MaxEvents 10

    Returns the 10 most recent Script Block Logging events only.
    These contain the actual script text that was executed.

.EXAMPLE
    PS> Get-PSRecentEvents -HoursBack 0 -MaxEvents 200 |
            Where-Object EventId -eq 4104 |
            Select-Object TimeCreated, Message |
            Format-List

    Dumps all Script Block Logging events in the log (no time limit),
    formatted for reading the full script content.

.EXAMPLE
    PS> Get-PSRecentEvents -EventId 4104 |
            Where-Object Message -match 'Invoke-Expression|IEX|EncodedCommand'

    Searches recent Script Block Logging events for common obfuscation
    and download-cradle patterns used in PowerShell-based attacks.

.OUTPUTS
    [PSCustomObject] One object per matching event with properties:
        ComputerName    - Machine where the event was generated
        TimeCreated     - Timestamp of the event
        EventId         - Windows event ID number
        Level           - Verbose | Information | Warning | Error | Critical
        LogName         - Source event log name
        UserId          - SID of the user context (if available)
        Message         - Full event message text

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Log      : Microsoft-Windows-PowerShell/Operational
    Prereq   : Script Block Logging and/or Module Logging must be enabled.
               Use Get-PSScriptBlockLogging and Get-PSModuleLogging to verify.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

.LINK
    https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-tracing-and-logging
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateRange(1, 10000)]
        [int] $MaxEvents = 50,

        [Parameter()]
        [ValidateRange(0, 8760)]   # 0 = no time limit; 8760 = 1 year
        [int] $HoursBack = 24,

        [Parameter()]
        [int[]] $EventId = @(4103, 4104, 4105, 4106),

        [Parameter()]
        [ValidateSet('WindowsPowerShell', 'PowerShell7', 'Both')]
        [string] $Engine = 'Both'
    )

    begin {
        $computerName = $env:COMPUTERNAME
        $targets = switch ($Engine) {
            'WindowsPowerShell' {
                @([PSCustomObject]@{ Engine = 'WindowsPowerShell'; LogName = 'Microsoft-Windows-PowerShell/Operational' })
            }
            'PowerShell7' {
                @([PSCustomObject]@{ Engine = 'PowerShell7'; LogName = 'PowerShellCore/Operational' })
            }
            default {
                @(
                    [PSCustomObject]@{ Engine = 'WindowsPowerShell'; LogName = 'Microsoft-Windows-PowerShell/Operational' }
                    [PSCustomObject]@{ Engine = 'PowerShell7'; LogName = 'PowerShellCore/Operational' }
                )
            }
        }

        Write-Verbose "[$computerName] Querying engine selection '$Engine' for Event IDs: $($EventId -join ', ')"
    }

    process {
        foreach ($target in $targets) {
            $filterParams = @{
                LogName = $target.LogName
                Id      = $EventId
            }

            if ($HoursBack -gt 0) {
                $filterParams['StartTime'] = (Get-Date).AddHours(-$HoursBack)
                Write-Verbose "[$computerName][$($target.Engine)] Time window: last $HoursBack hours (since $($filterParams['StartTime']))"
            }

            $events = Get-WinEvent -FilterHashtable $filterParams -MaxEvents $MaxEvents `
                          -ErrorAction SilentlyContinue

            if (-not $events) {
                Write-Verbose "[$computerName][$($target.Engine)] No events found in $($target.LogName)."
                continue
            }

            Write-Verbose "[$computerName][$($target.Engine)] Found $($events.Count) event(s)."

            foreach ($evt in $events) {
                [PSCustomObject]@{
                    ComputerName = $computerName
                    Engine       = $target.Engine
                    TimeCreated  = $evt.TimeCreated
                    EventId      = $evt.Id
                    Level        = $evt.LevelDisplayName
                    LogName      = $evt.LogName
                    UserId       = $evt.UserId
                    Message      = $evt.Message
                }
            }
        }
    }
}
