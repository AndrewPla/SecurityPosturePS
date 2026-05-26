function Get-WinRMPolicy {
<#
.SYNOPSIS
    Reads the WinRM (PowerShell Remoting) Group Policy state from the registry.

.DESCRIPTION
    Windows Remote Management (WinRM) is the service that powers PowerShell
    Remoting (Enter-PSSession, Invoke-Command, etc.). When enabled, it opens
    a network listener that accepts incoming PowerShell connections.

    This function checks whether WinRM has been enabled by Group Policy via
    the AllowAutoConfig value. A result of 'Enabled' means policy has turned
    on WinRM across the machine. 'Not Configured' means the GPO is not
    applying this setting -- WinRM may still be running if it was enabled
    manually or by another mechanism, so this check is not definitive.

    SECURITY CONTEXT
    Remoting enabled without proper controls is a lateral-movement risk:
      - Require Kerberos or certificate authentication (not NTLM)
      - Restrict access with firewall rules and JEA (Just Enough Administration)
      - Log all remoting sessions via transcription or a PSSession transcript

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Depends on your environment. On servers that intentionally accept remote
    management: 'Enabled' is expected. On workstations: 'Not Configured' or
    'Disabled' is preferred unless WinRM is explicitly required.

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows Remote Management (WinRM)
         > WinRM Service
         > Allow remote server management through WinRM  ->  Enabled/Disabled

    This function is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-WinRMPolicy

    Returns the WinRM Group Policy state for the local machine.

.EXAMPLE
    PS> Get-WinRMPolicy | Select-Object ComputerName, Status, Notes

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enabled  0 = Disabled  absent = Not Configured
    Caveat   : 'Not Configured' here does not mean WinRM is off -- check
               Get-Service WinRM and netstat for the actual listener state.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements

.LINK
    https://learn.microsoft.com/en-us/windows/win32/winrm/portal
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking WinRM Group Policy state..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
        $value   = (Get-ItemProperty -Path $regPath -Name 'AllowAutoConfig' `
                        -ErrorAction SilentlyContinue).AllowAutoConfig

        $status = switch ($value) {
            1       { 'Enabled'        }
            0       { 'Disabled'       }
            default { 'Not Configured' }
        }

        Write-Verbose "[$computerName] WinRM AllowAutoConfig => $status (raw: $value)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'PowerShell Remoting Policy (WinRM)'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'AllowAutoConfig'
            CurrentValue = $value
            Notes        = 'Indicates whether WinRM is enabled by Group Policy; remoting without firewall controls or JEA constraints is a significant lateral-movement surface.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements'
        }
    }
}
