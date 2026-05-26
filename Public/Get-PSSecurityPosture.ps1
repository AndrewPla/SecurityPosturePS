function Get-PSSecurityPosture {
<#
.SYNOPSIS
    Runs all SecurityPosturePS checks and returns a consolidated security report.

.DESCRIPTION
    Get-PSSecurityPosture is the top-level entry point for SecurityPosturePS.
    It calls every individual audit function in the module and returns their
    results as a single, unified collection of [PSCustomObject] records --
    one per check.

    Because each individual function returns objects with the same property
    schema (ComputerName, CheckName, Status, RegistryPath, ValueName,
    CurrentValue, Notes, Reference), the combined output is fully pipeline-
    friendly. You can filter, sort, export, or convert the entire report
    with standard PowerShell cmdlets.

    CHECKS INCLUDED
      PowerShell Logging
        - Script Block Logging         (Get-PSScriptBlockLogging)
        - Script Block Invocation      (Get-PSInvocationLogging)
        - Module Logging               (Get-PSModuleLogging)
        - Transcription                (Get-PSTranscription)
        - Protected Event Logging      (Get-PSProtectedEventLogging)

      Execution Controls
        - Machine Execution Policy     (Get-PSMachineExecutionPolicy)
        - AppLocker Script Rules       (Get-AppLockerScriptRules)

      Host Defense
        - WD Real-Time Protection      (Get-WDRealTimeProtection)
        - PowerShell Remoting / WinRM  (Get-WinRMPolicy)

            Event Log Configuration
                - PS/Operational log health    (Get-PSEventLogConfig)
                - PowerShell 7 log health
                - Windows PowerShell log health
                - AppLocker/MSI and Script log health
                - Windows Defender log health

            Inventory
        - Installed PS Versions        (Get-PSVersionInfo)

    HOW TO USE THIS MODULE FOR LEARNING
    Run Get-PSSecurityPosture, find a result you don't understand, then follow
    the Reference URL in that object's Reference property to the official
    Microsoft Learn documentation. Every check is designed to teach as it audits.

    This function is entirely read-only. To remediate findings, use Group Policy
    (the preferred production mechanism) or consult the Reference URL for each
    check. Do not use scripts to enforce security settings in production -- use
    GPO so settings are managed, versioned, and re-applied on refresh.

.EXAMPLE
    PS> Get-PSSecurityPosture

    Runs all checks and returns every result.

.EXAMPLE
    PS> Get-PSSecurityPosture | Format-Table CheckName, Status -AutoSize

    Quick overview table of every check and its current state.

.EXAMPLE
    PS> Get-PSSecurityPosture | Where-Object { $_.Status -notin 'Enabled','Installed','Configured','Enforced' }

    Shows only checks that are not in a desirable state -- a fast gap report.

.EXAMPLE
    PS> Get-PSSecurityPosture | Where-Object Status -in 'Disabled','Not Configured' |
            Select-Object CheckName, Status, Notes, Reference |
            Format-List

    Shows each failing check with its plain-English explanation and the
    Microsoft Learn URL to read before remediating.

.EXAMPLE
    PS> Get-PSSecurityPosture | Export-Csv -Path .\SecurityPosture.csv -NoTypeInformation

    Exports the full report to CSV for compliance evidence or SIEM import.

.EXAMPLE
    PS> Get-PSSecurityPosture | ConvertTo-Json | Out-File .\SecurityPosture.json

    Exports the report as JSON for ingestion into a dashboard or log platform.

.OUTPUTS
    [PSCustomObject[]]
    A collection of objects, one per check. All objects share the same schema:
        ComputerName  - Machine audited
        CheckName     - Human-readable check name
        Status        - Enabled | Disabled | Configured | Not Configured |
                        Enforced | Audit Only | Installed | Not Installed |
                        <PolicyName> (for Execution Policy)
        RegistryPath  - Registry path examined
        ValueName     - Registry value name examined
        CurrentValue  - Raw value found ($null if key absent)
        Notes         - One-sentence explanation of the setting and why it matters
        Reference     - Official Microsoft Learn or guidance URL

.NOTES
    Module  : SecurityPosturePS v0.1.0
    This function calls all Get-PS* and related functions in this module.
    Run individual functions (e.g. Get-PSScriptBlockLogging) when you want
    to inspect a single check in isolation or with -Verbose detail.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies

.LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        Write-Verbose "[$env:COMPUTERNAME] Starting full security posture audit..."

        # Pass -Verbose through to each sub-function when the caller uses -Verbose.
        $verboseOn = $PSBoundParameters.ContainsKey('Verbose') -and $Verbose
        $common    = if ($verboseOn) { @{ Verbose = $true } } else { @{} }
    }

    process {
        # ── PowerShell Logging ────────────────────────────────────────────────
        Get-PSScriptBlockLogging    @common
        Get-PSInvocationLogging     @common
        Get-PSModuleLogging         @common
        Get-PSTranscription         @common
        Get-PSProtectedEventLogging @common

        # ── Execution Controls ────────────────────────────────────────────────
        Get-PSMachineExecutionPolicy @common
        Get-AppLockerScriptRules     @common

        # ── Host Defense ──────────────────────────────────────────────────────
        Get-WDRealTimeProtection @common
        Get-WinRMPolicy          @common

        # ── Event Log Configuration ───────────────────────────────────────────
        # Verifies that the logs receiving security events are enabled and
        # large enough to retain forensically useful data.
        Get-PSEventLogConfig @common

        # ── Inventory ─────────────────────────────────────────────────────────
        Get-PSVersionInfo @common
    }

    end {
        Write-Verbose "[$env:COMPUTERNAME] Security posture audit complete."
    }
}
