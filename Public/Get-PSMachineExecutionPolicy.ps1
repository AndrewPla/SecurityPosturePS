function Get-PSMachineExecutionPolicy {
<#
.SYNOPSIS
    Reads the machine-scope PowerShell Execution Policy from the registry.

.DESCRIPTION
    The Execution Policy controls which scripts PowerShell is permitted to run.
    The machine scope (HKLM) applies to all users on the machine and overrides
    user-scope settings. Policies range from most to least restrictive:

        Restricted     - No scripts allowed (interactive commands only)
        AllSigned      - Only scripts signed by a trusted publisher
        RemoteSigned   - Local scripts run freely; downloaded scripts must be signed
        Unrestricted   - All scripts run; user is prompted for downloaded scripts
        Bypass         - Nothing is blocked, no warnings -- scripts always run

    A machine-scope policy of 'Bypass' or 'Unrestricted' defeats all
    user-level policies and renders AppLocker script rules less effective,
    since PowerShell itself won't enforce any signing requirement.

    This function reports the raw policy string as the Status value (e.g.
    'RemoteSigned') rather than Enabled/Disabled, because the policy name
    itself is the meaningful data. If no machine-scope policy is set in the
    registry, Group Policy or the default applies.

    This function is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'AllSigned' or 'RemoteSigned'
    Status = 'Bypass' or 'Unrestricted' warrants investigation.

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows PowerShell
         > Turn on Script Execution  ->  Enabled
           Execution Policy: Allow only signed scripts  (= AllSigned)

    Do not use Set-ExecutionPolicy for production enforcement -- it writes to
    the same registry key this function reads, so it can be overwritten by any
    local administrator. Group Policy re-applies on refresh and cannot be
    overridden by Set-ExecutionPolicy.

    This function is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-PSMachineExecutionPolicy

    Returns the machine-scope execution policy for the local machine.

.EXAMPLE
    PS> Get-PSMachineExecutionPolicy |
            Where-Object { $_.Status -in 'Bypass', 'Unrestricted' }

    Alerts when the execution policy is in a permissive state.

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

    Note: Status contains the policy name string (e.g. 'RemoteSigned'),
    not a simple Enabled/Disabled value.

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : String (REG_SZ)
    See also : Get-AppLockerScriptRules for application-control enforcement.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking Machine Execution Policy..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
        $value   = (Get-ItemProperty -Path $regPath -Name 'ExecutionPolicy' `
                        -ErrorAction SilentlyContinue).ExecutionPolicy

        # Report the raw policy name as Status -- it IS the meaningful data here.
        $status = if ($value) { $value } else { 'Not Configured' }

        Write-Verbose "[$computerName] Machine Execution Policy => $status"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'Machine Execution Policy'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'ExecutionPolicy'
            CurrentValue = $value
            Notes        = 'A machine-scope policy of Bypass or Unrestricted allows any script to run regardless of signing, overriding all user-level policies and reducing AppLocker effectiveness.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies'
        }
    }
}
