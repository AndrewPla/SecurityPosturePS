function Get-WDRealTimeProtection {
<#
.SYNOPSIS
    Reads the Windows Defender Real-Time Monitoring state from the local registry.

.DESCRIPTION
    Windows Defender Real-Time Protection monitors file system activity,
    process creation, network connections, and other system events in real
    time to detect and block malware before it can execute. Disabling it
    leaves the machine with no active AV scanning.

    INVERTED REGISTRY LOGIC
    The registry value is named 'DisableRealtimeMonitoring'. A value of 1
    means protection is OFF. A value of 0, or the absence of the key entirely,
    means protection is ON (the default). This function normalises that
    inversion: Status = 'Enabled' always means "protection is active",
    and Status = 'Disabled' always means "protection is turned off".

    A 'Disabled' result here is a high-confidence indicator of a problem:
    it means a Group Policy object has explicitly turned off AV scanning,
    which is a technique used by attackers and ransomware to avoid detection.

    This function reads a single registry DWORD and returns the current state
    as a labelled [PSCustomObject]. It is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    Status = 'Enabled'  (CurrentValue = 0 or $null)

    HOW TO CONFIGURE THIS IN PRODUCTION
    Real-Time Protection should be ON by default. If it is showing as Disabled,
    investigate the GPO that is applying this setting. The policy path is:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Microsoft Defender Antivirus
         > Real-time Protection
         > Turn off real-time protection  ->  should be Disabled (or Not Configured)

    This function is a learning and auditing tool, not a configuration tool.

.EXAMPLE
    PS> Get-WDRealTimeProtection

    Returns the current Windows Defender real-time protection state.

.EXAMPLE
    PS> Get-WDRealTimeProtection | Where-Object Status -eq 'Disabled'

    Alerts when real-time protection has been explicitly disabled via policy.

.OUTPUTS
    [PSCustomObject] with properties:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

    Note: CurrentValue = 1 means DISABLED (the registry value is inverted).

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg type : DWORD  0 or absent = protection ON (Enabled)  1 = protection OFF (Disabled)
    Warning  : Status='Disabled' means AV real-time scanning is not active.

.LINK
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking Windows Defender Real-Time Protection..."
    }

    process {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $value   = (Get-ItemProperty -Path $regPath -Name 'DisableRealtimeMonitoring' `
                        -ErrorAction SilentlyContinue).DisableRealtimeMonitoring

        # Inverted: DisableRealtimeMonitoring = 1 means protection is OFF.
        $status = switch ($value) {
            1       { 'Disabled' }   # Protection is OFF -- bad
            0       { 'Enabled'  }   # Protection is ON  -- good
            default { 'Enabled'  }   # Key absent = default ON
        }

        Write-Verbose "[$computerName] WD Real-Time Protection => $status (raw: $value)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'WD Real-Time Protection'
            Status       = $status
            RegistryPath = $regPath
            ValueName    = 'DisableRealtimeMonitoring'
            CurrentValue = $value
            Notes        = 'A GPO value of 1 disables Windows Defender real-time scanning entirely; this is a known attacker technique to prevent AV from detecting or blocking malicious activity.'
            Reference    = 'https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus'
        }
    }
}
