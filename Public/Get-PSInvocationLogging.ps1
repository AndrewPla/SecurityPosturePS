function Get-PSInvocationLogging {
<#
.SYNOPSIS
    Reads the Script Block Invocation Logging (deep logging) state from the registry.

.DESCRIPTION
    Script Block Invocation Logging extends standard Script Block Logging by
    also emitting event IDs when a script block starts and stops executing,
    not just logging its content. This enables timing-based forensic analysis:
    you can reconstruct the exact sequence and duration of every script block
    that ran during an incident.

    IMPORTANT: This setting has no effect unless Script Block Logging
    (EnableScriptBlockLogging) is also enabled. Run Get-PSScriptBlockLogging
    alongside this function to verify both are active.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enabled'  (CurrentValue = 1)
    AND Get-PSScriptBlockLogging also returns Status = 'Enabled'

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy -- the same policy that enables Script Block Logging has
    a sub-option for invocation logging:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows PowerShell
         > Turn on PowerShell Script Block Logging  ->  Enabled
           [x] Log script block invocation start / stop events

    This function shows you which registry key that option writes to.
    It is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-PSInvocationLogging

    Returns the current invocation logging state for the local machine.

.EXAMPLE
    PS> Get-PSScriptBlockLogging, (Get-PSInvocationLogging) | Format-Table CheckName, Status

    Checks both Script Block Logging and Invocation Logging together, since
    Invocation Logging is only meaningful when Script Block Logging is also on.

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enabled  0 = Disabled  absent = Not Configured
    Depends  : Get-PSScriptBlockLogging must also be Enabled for this to work.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [ValidateSet('WindowsPowerShell', 'PowerShell7', 'Both')]
        [string] $Engine = 'Both'
    )

    begin {
        $computerName = $env:COMPUTERNAME
        $targets = switch ($Engine) {
            'WindowsPowerShell' {
                @([PSCustomObject]@{
                    Engine  = 'WindowsPowerShell'
                    RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                })
            }
            'PowerShell7' {
                @([PSCustomObject]@{
                    Engine  = 'PowerShell7'
                    RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
                })
            }
            default {
                @(
                    [PSCustomObject]@{
                        Engine  = 'WindowsPowerShell'
                        RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                    }
                    [PSCustomObject]@{
                        Engine  = 'PowerShell7'
                        RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging'
                    }
                )
            }
        }

        Write-Verbose "[$computerName] Checking Script Block Invocation Logging for engine selection: $Engine"
    }

    process {
        foreach ($target in $targets) {
            $regPath = $target.RegPath
            $value   = (Get-ItemProperty -Path $regPath -Name 'EnableScriptBlockInvocationLogging' `
                            -ErrorAction SilentlyContinue).EnableScriptBlockInvocationLogging

            $status = switch ($value) {
                1       { 'Enabled'        }
                0       { 'Disabled'       }
                default { 'Not Configured' }
            }

            Write-Verbose "[$computerName][$($target.Engine)] Script Block Invocation Logging => $status (raw: $value)"

            [PSCustomObject]@{
                ComputerName = $computerName
                CheckName    = "Script Block Invocation Logging ($($target.Engine))"
                Engine       = $target.Engine
                Status       = $status
                RegistryPath = $regPath
                ValueName    = 'EnableScriptBlockInvocationLogging'
                CurrentValue = $value
                Notes        = "Extends Script Block Logging for $($target.Engine) with start and stop event markers, enabling timing-based forensic analysis of when each script block executed relative to others."
                Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
        }
    }
}
