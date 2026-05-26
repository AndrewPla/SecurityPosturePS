function Get-AppLockerRecentEvents {
<#
.SYNOPSIS
    Queries recent AppLocker script enforcement events from the Windows event log.

.DESCRIPTION
    Get-AppLockerRecentEvents reads the Microsoft-Windows-AppLocker/MSI and Script
    log and returns events that show what the AppLocker script policy has been
    doing: what was allowed, what was audited (would have been blocked), and
    what was actually blocked.

    APPLOCKER SCRIPT EVENT IDS
      8005  Script was allowed by a rule
      8006  Script was allowed but WOULD have been blocked in Enforce mode
            (this is the audit mode event -- critical for policy tuning)
      8007  Script was blocked by a rule (Enforce mode only)

    Event 8006 is the most operationally useful during a baseline review:
    it tells you what would break if you switched from Audit Only to Enforced
    mode, without actually blocking anything. Use this to tune allow rules
    before flipping to enforcement.

    RELATIONSHIP TO Get-AppLockerScriptRules
    Use Get-AppLockerScriptRules to see whether AppLocker is enforced or in
    audit mode (registry configuration). Use this function to see the actual
    events that enforcement or auditing is generating.

    BEFORE USING THIS FUNCTION
    AppLocker must be configured with script rules for events to appear here.
    The Application Identity service (AppIDSvc) must be running.
    Check with: Get-Service AppIDSvc

    This function is read-only.

.PARAMETER MaxEvents
    Maximum number of events to return. Default: 50.

.PARAMETER HoursBack
    How many hours back to search. Default: 24.
    Set to 0 to return all available events up to -MaxEvents.

.PARAMETER EventId
    One or more specific event IDs to filter on.
    Default: 8005, 8006, 8007 (all AppLocker script event IDs).
    Use @(8006, 8007) to focus on violations only.

.EXAMPLE
    PS> Get-AppLockerRecentEvents

    Returns up to 50 AppLocker script events from the last 24 hours.

.EXAMPLE
    PS> Get-AppLockerRecentEvents -EventId 8006, 8007

    Returns only audit violations (8006) and hard blocks (8007) --
    the events that indicate something was not explicitly permitted.

.EXAMPLE
    PS> Get-AppLockerRecentEvents -EventId 8006 -HoursBack 168 -MaxEvents 500

    Shows everything that WOULD be blocked if AppLocker were switched from
    Audit Only to Enforced mode over the last 7 days. Use this to tune rules
    before enforcement.

.EXAMPLE
    PS> Get-AppLockerRecentEvents -EventId 8007 |
            Select-Object TimeCreated, Message |
            Format-List

    Lists recent hard-blocked script attempts with full event details.

.OUTPUTS
    [PSCustomObject] One object per matching event with properties:
        ComputerName    - Machine where the event was generated
        TimeCreated     - Timestamp of the event
        EventId         - 8005 (allowed) | 8006 (audit/would-block) | 8007 (blocked)
        Level           - Event severity level
        LogName         - Microsoft-Windows-AppLocker/MSI and Script
        PolicyDecision  - Allowed | AuditOnly | Blocked (derived from EventId)
        Message         - Full event message (includes the file path and rule name)

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Log      : Microsoft-Windows-AppLocker/MSI and Script
    Prereq   : AppLocker script rules must be configured and AppIDSvc running.
               Use Get-AppLockerScriptRules to verify the policy configuration.
    See also : Get-PSRecentEvents for PowerShell-specific security events.

.LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview

.LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/using-event-viewer-with-applocker
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateRange(1, 10000)]
        [int] $MaxEvents = 50,

        [Parameter()]
        [ValidateRange(0, 8760)]
        [int] $HoursBack = 24,

        [Parameter()]
        [int[]] $EventId = @(8005, 8006, 8007)
    )

    begin {
        $computerName = $env:COMPUTERNAME
        $logName      = 'Microsoft-Windows-AppLocker/MSI and Script'

        # Human-readable label for each event ID -- used to populate PolicyDecision.
        $decisionMap = @{
            8005 = 'Allowed'
            8006 = 'Audit Only (would have been blocked)'
            8007 = 'Blocked'
        }

        Write-Verbose "[$computerName] Querying '$logName' for Event IDs: $($EventId -join ', ')"
    }

    process {
        $filterParams = @{
            LogName = $logName
            Id      = $EventId
        }

        if ($HoursBack -gt 0) {
            $filterParams['StartTime'] = (Get-Date).AddHours(-$HoursBack)
            Write-Verbose "[$computerName] Time window: last $HoursBack hours"
        }

        $events = Get-WinEvent -FilterHashtable $filterParams -MaxEvents $MaxEvents `
                      -ErrorAction SilentlyContinue

        if (-not $events) {
            Write-Verbose "[$computerName] No AppLocker script events found. Verify script rules are configured with Get-AppLockerScriptRules and that AppIDSvc is running."
            return
        }

        Write-Verbose "[$computerName] Found $($events.Count) AppLocker event(s)."

        foreach ($evt in $events) {
            [PSCustomObject]@{
                ComputerName   = $computerName
                TimeCreated    = $evt.TimeCreated
                EventId        = $evt.Id
                Level          = $evt.LevelDisplayName
                LogName        = $evt.LogName
                PolicyDecision = $decisionMap[$evt.Id] ?? "Unknown (ID $($evt.Id))"
                Message        = $evt.Message
            }
        }
    }
}
