function Get-EventLogClearEvent {
<#
.SYNOPSIS
    Finds recent Windows event log clear events.

.DESCRIPTION
    Queries for Event ID 104 from the System log and Event ID 1102 from the Security log.

    Event ID 104 means a Windows event log was cleared.
    Event ID 1102 means the Security audit log was cleared.

.PARAMETER HoursBack
    Number of hours back to search. Default is 24. Use 0 for all available events.

.PARAMETER MaxEvents
    Maximum events to return per event type.

.EXAMPLE
    Get-EventLogClearEvent

.EXAMPLE
    Get-EventLogClearEvent -HoursBack 168 -MaxEvents 100
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateRange(0, 8760)]
        [int] $HoursBack = 24,

        [Parameter()]
        [ValidateRange(1, 10000)]
        [int] $MaxEvents = 100
    )

    $computerName = $env:COMPUTERNAME

    $startTime = if ($HoursBack -gt 0) {
        (Get-Date).AddHours(-$HoursBack)
    }
    else {
        $null
    }

    $queries = @(
        [pscustomobject]@{
            LogName     = 'System'
            Id          = 104
            Meaning     = 'A Windows event log was cleared.'
            Severity    = 'High'
        }
        [pscustomobject]@{
            LogName     = 'Security'
            Id          = 1102
            Meaning     = 'The Security audit log was cleared.'
            Severity    = 'Critical'
        }
    )

    foreach ($query in $queries) {
        $filter = @{
            LogName = $query.LogName
            Id      = $query.Id
        }

        if ($startTime) {
            $filter.StartTime = $startTime
        }

        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue

        foreach ($event in $events) {
            [pscustomobject]@{
                ComputerName = $computerName
                TimeCreated  = $event.TimeCreated
                EventId      = $event.Id
                LogName      = $event.LogName
                ProviderName = $event.ProviderName
                Meaning      = $query.Meaning
                Severity     = $query.Severity
                UserId       = $event.UserId
                Message      = $event.Message
            }
        }
    }
}