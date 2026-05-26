function Get-PSScriptBlockLogging {
<#
.SYNOPSIS
    Reads the Script Block Logging state from the local registry.

.DESCRIPTION
    Script Block Logging records the full decoded content of every PowerShell
    script block at execution time -- including obfuscated or dynamically
    generated code -- and writes it to the Windows PowerShell event log
    (Event ID 4104). This is one of the most valuable detections available
    for PowerShell-based attacks that use Invoke-Expression or Base64 payloads.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enabled'  (CurrentValue = 1)

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy -- not a script -- so the setting is managed and auditable:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows PowerShell
         > Turn on PowerShell Script Block Logging  ->  Enabled

    This function shows you exactly which registry key that policy writes to
    and whether it is currently active. It is a learning and auditing tool,
    not a configuration tool.

.EXAMPLE
    PS> Get-PSScriptBlockLogging

    Returns the current Script Block Logging state for the local machine.

.EXAMPLE
    PS> Get-PSScriptBlockLogging | Select-Object Status, Notes, Reference

    Shows the status, a plain-English explanation, and the Microsoft Learn URL.

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enabled  0 = Disabled  absent = Not Configured
    See also : Get-PSInvocationLogging for deeper invocation start/stop events.

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

        Write-Verbose "[$computerName] Checking Script Block Logging for engine selection: $Engine"
    }

    process {
        foreach ($target in $targets) {
            $regPath = $target.RegPath
            $value   = (Get-ItemProperty -Path $regPath -Name 'EnableScriptBlockLogging' `
                            -ErrorAction SilentlyContinue).EnableScriptBlockLogging

            $status = switch ($value) {
                1       { 'Enabled'        }
                0       { 'Disabled'       }
                default { 'Not Configured' }
            }

            Write-Verbose "[$computerName][$($target.Engine)] Script Block Logging => $status (raw: $value)"

            [PSCustomObject]@{
                ComputerName = $computerName
                CheckName    = "Script Block Logging ($($target.Engine))"
                Engine       = $target.Engine
                Status       = $status
                RegistryPath = $regPath
                ValueName    = 'EnableScriptBlockLogging'
                CurrentValue = $value
                Notes        = "Records the full content of every PowerShell script block at execution time for $($target.Engine), enabling forensic review of obfuscated or dynamically generated malicious code."
                Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
            }
        }
    }
}
