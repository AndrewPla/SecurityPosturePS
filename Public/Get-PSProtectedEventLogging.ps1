function Get-PSProtectedEventLogging {
<#
.SYNOPSIS
    Reads the Protected Event Logging state from the local registry.

.DESCRIPTION
    Protected Event Logging encrypts PowerShell event log entries using a
    public key (CMS / Cryptographic Message Syntax) before they are written
    to the Windows event log. Only the holder of the corresponding private key
    -- typically a designated SIEM service account or log analysis server --
    can decrypt and read the log content.

    Without this, an attacker who gains read access to the Windows event log
    (which is not restricted by default) can read everything that was logged,
    including any secrets or credentials that appeared in a script. Protected
    Event Logging closes that gap.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enabled'  (CurrentValue = 1)
    AND a valid certificate thumbprint is configured in the same policy.

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Event Logging
         > Enable Protected Event Logging  ->  Enabled

    You must also provide an encryption certificate (as a Base64 CMS blob)
    in the Encryption Certificate policy field. The private key for decryption
    should be held only by your log analysis infrastructure.

    See the Microsoft Learn link below for a full walkthrough of generating
    and deploying the certificate.

    This function is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-PSProtectedEventLogging

    Returns the current Protected Event Logging state for the local machine.

.EXAMPLE
    PS> Get-PSProtectedEventLogging | Select-Object Status, Notes, Reference

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  1 = Enabled  0 = Disabled  absent = Not Configured

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_non-windows
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking Protected Event Logging..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging'
        $value   = (Get-ItemProperty -Path $regPath -Name 'EnableProtectedEventLogging' `
                        -ErrorAction SilentlyContinue).EnableProtectedEventLogging

        $status = switch ($value) {
            1       { 'Enabled'        }
            0       { 'Disabled'       }
            default { 'Not Configured' }
        }

        Write-Verbose "[$computerName] Protected Event Logging => $status (raw: $value)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'Protected Event Logging'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'EnableProtectedEventLogging'
            CurrentValue = $value
            Notes        = 'Encrypts PowerShell event log entries with a CMS certificate so an attacker with event log access cannot read logged script content or embedded secrets.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows'
        }
    }
}
