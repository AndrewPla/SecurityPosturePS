function Get-PSModuleLogging {
<#
.SYNOPSIS
    Reads the Module Logging state from the local registry.

.DESCRIPTION
    Module Logging writes pipeline execution events for PowerShell modules to
    the Windows PowerShell event log (Event ID 4103). It captures each
    command's inputs, outputs, and the module it came from. Unlike Script Block
    Logging, it operates at the pipeline level rather than the source-code
    level, and only logs modules you explicitly include in the policy.

    A common best-practice configuration is to enable this for all modules
    by setting the module name list to '*'.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enabled'  (CurrentValue = 1)

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows PowerShell
         > Turn on Module Logging  ->  Enabled

    Then specify which modules to log in the Module Names sub-option.
    Use '*' to log all modules.

    This function shows you which registry key that policy writes to and
    whether it is currently active. It is a learning and auditing tool,
    not a configuration tool.

.EXAMPLE
    PS> Get-PSModuleLogging

    Returns the current Module Logging state for the local machine.

.EXAMPLE
    PS> Get-PSModuleLogging | Select-Object Status, Notes, Reference

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enabled  0 = Disabled  absent = Not Configured
    See also : Get-PSScriptBlockLogging for source-code-level logging.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking Module Logging..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
        $value   = (Get-ItemProperty -Path $regPath -Name 'EnableModuleLogging' `
                        -ErrorAction SilentlyContinue).EnableModuleLogging

        $status = switch ($value) {
            1       { 'Enabled'        }
            0       { 'Disabled'       }
            default { 'Not Configured' }
        }

        Write-Verbose "[$computerName] Module Logging => $status (raw: $value)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'Module Logging'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'EnableModuleLogging'
            CurrentValue = $value
            Notes        = 'Logs all pipeline execution events for specified PowerShell modules to the Windows event log, providing visibility into module-level activity without requiring script block logging.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
        }
    }
}
