function Get-AppLockerScriptRules {
<#
.SYNOPSIS
    Reads the AppLocker Script Rules enforcement mode from the local registry.

.DESCRIPTION
    AppLocker Script Rules control which PowerShell scripts, VBScript, JScript,
    batch files, and Windows Script Host files are permitted to execute. When
    enforced, AppLocker blocks any script that does not match an allow rule,
    making it significantly harder for attackers to run arbitrary code even if
    they can drop a file to disk.

    The enforcement mode has three possible states:
        Not Configured  - No AppLocker script policy is applied
        Audit Only      - Policy violations are logged but scripts are NOT blocked
        Enforced        - Non-matching scripts are blocked and logged

    'Audit Only' is commonly used during roll-out to identify what would be
    blocked before enforcement, but it provides zero runtime protection.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enforced'  (CurrentValue = 1)

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Windows Settings
         > Security Settings
         > Application Control Policies
         > AppLocker
         > Script Rules  ->  Configure rule enforcement

    The Application Identity service (AppIDSvc) must be running for AppLocker
    to enforce rules. Check this separately with: Get-Service AppIDSvc

    This function is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-AppLockerScriptRules

    Returns the current AppLocker script enforcement mode.

.EXAMPLE
    PS> Get-AppLockerScriptRules | Where-Object Status -ne 'Enforced'

    Surfaces machines where AppLocker is not actively enforcing script rules.

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

    Status values: Enforced | Audit Only | Not Configured

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enforced  2 = Audit Only  absent = Not Configured
    Prereq   : The AppIDSvc service must be running for enforcement to work.

.LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview

.LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/requirements-to-use-applocker
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking AppLocker Script Rules..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script'
        $value   = (Get-ItemProperty -Path $regPath -Name 'EnforcementMode' `
                        -ErrorAction SilentlyContinue).EnforcementMode

        $status = switch ($value) {
            1       { 'Enforced'       }
            2       { 'Audit Only'     }
            default { 'Not Configured' }
        }

        Write-Verbose "[$computerName] AppLocker Script Rules => $status (raw: $value)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'AppLocker Script Rules'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'EnforcementMode'
            CurrentValue = $value
            Notes        = 'AppLocker script rules control which scripts may execute; Audit Only logs violations without blocking them and provides no runtime protection against malicious scripts.'
            Reference    = 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview'
        }
    }
}
