function Get-PSTranscription {
<#
.SYNOPSIS
    Reads the PowerShell Transcription configuration from the local registry.

.DESCRIPTION
    PowerShell Transcription writes a plain-text log of every PowerShell
    session -- all input commands and their output -- to a file on disk.
    Unlike event log entries, transcripts are immediately human-readable
    without a SIEM query and capture exactly what a user saw on screen.

    This function checks two related registry values under the same key:
      1. EnableTranscripting  - whether transcription is turned on at all
      2. OutputDirectory      - where transcript files are written

    Both are returned as separate [PSCustomObject] entries so you can
    independently filter on "is transcription on?" and "is a central
    log path configured?".

    This function is entirely read-only.

    WHAT "GOOD" LOOKS LIKE
    EnableTranscripting  -> Status = 'Enabled'
    OutputDirectory      -> Status = 'Configured'  (ideally a UNC path)

    HOW TO CONFIGURE THIS IN PRODUCTION
    Use Group Policy:

        Computer Configuration
         > Administrative Templates
         > Windows Components
         > Windows PowerShell
         > Turn on PowerShell Transcription  ->  Enabled

    Set the Output Directory to a centralised UNC share (e.g. \\logs\PSTranscripts)
    so transcripts from all machines are aggregated in one place.

    This function shows you which registry keys that policy writes to and
    their current values. It is a learning and auditing tool, not a
    configuration tool.

.EXAMPLE
    PS> Get-PSTranscription

    Returns both the transcription-enabled check and the output directory
    check for the local machine.

.EXAMPLE
    PS> Get-PSTranscription | Where-Object Status -notin 'Enabled','Configured'

    Shows only checks that are not in the desired state.

.OUTPUTS
    [PSCustomObject[]] Two objects per call:
      1. EnableTranscripting  - Status: Enabled | Disabled | Not Configured
      2. OutputDirectory      - Status: Configured | Not Configured

    Both objects share the same property set:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    Reg path : HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    See also : Get-PSScriptBlockLogging, Get-PSModuleLogging

.LINK
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_transcripts
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        $regPath      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
        Write-Verbose "[$computerName] Checking PowerShell Transcription..."
    }

    process {
        # ── Transcription enabled ─────────────────────────────────────────────
        $enableValue = (Get-ItemProperty -Path $regPath -Name 'EnableTranscripting' `
                            -ErrorAction SilentlyContinue).EnableTranscripting

        $enableStatus = switch ($enableValue) {
            1       { 'Enabled'        }
            0       { 'Disabled'       }
            default { 'Not Configured' }
        }

        Write-Verbose "[$computerName] Transcription => $enableStatus (raw: $enableValue)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'PowerShell Transcription'
            Status       = $enableStatus
            RegistryPath = $regPath
            ValueName    = 'EnableTranscripting'
            CurrentValue = $enableValue
            Notes        = 'Writes a complete transcript of each PowerShell session -- input and output -- to a log file, providing a human-readable audit trail for incident response.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_transcripts'
        }

        # ── Output directory ──────────────────────────────────────────────────
        $dirValue  = (Get-ItemProperty -Path $regPath -Name 'OutputDirectory' `
                          -ErrorAction SilentlyContinue).OutputDirectory
        $dirStatus = if ($dirValue) { 'Configured' } else { 'Not Configured' }

        Write-Verbose "[$computerName] Transcription OutputDirectory => $dirStatus (value: $dirValue)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'Transcription Output Directory'
            Status       = $dirStatus
            RegistryPath = $regPath
            ValueName    = 'OutputDirectory'
            CurrentValue = $dirValue
            Notes        = 'Specifies where transcript files are written; a centralised UNC path (e.g. \\fileserver\PSTranscripts) enables SIEM aggregation across all machines in the environment.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_transcripts'
        }
    }
}
