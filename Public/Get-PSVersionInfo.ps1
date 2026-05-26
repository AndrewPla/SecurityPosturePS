function Get-PSVersionInfo {
<#
.SYNOPSIS
    Reports the installed versions of Windows PowerShell and PowerShell 7+ (Core).

.DESCRIPTION
    This function checks two separate registry locations to enumerate every
    version of PowerShell present on the machine:

      1. Windows PowerShell (5.1)
         Always present on modern Windows. The registry engine key reports the
         exact build version (e.g. 5.1.19041.5614), which tells you whether
         the latest Windows cumulative update has been applied.

      2. PowerShell 7+ (Core)
         An optional, separately installed runtime. Each installed version
         registers itself under a unique GUID subkey, so this function captures
         all side-by-side installs. Stale or end-of-life versions should be
         removed or updated.

    PowerShell 7 support lifecycle: https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle

    This function is informational -- it does not evaluate a pass/fail security
    posture for these checks. Use the version numbers returned to cross-reference
    against the current supported release list.

    This function is entirely read-only.

.EXAMPLE
    PS> Get-PSVersionInfo

    Returns one object for Windows PowerShell and one for PowerShell 7+ Core.

.EXAMPLE
    PS> Get-PSVersionInfo | Format-Table CheckName, Status, CurrentValue -AutoSize

    Displays a compact version summary table.

.OUTPUTS
    [PSCustomObject[]] Two objects:
      1. Windows PowerShell Version - Status: Installed | Not Found
      2. PowerShell 7+ Installed    - Status: Installed | Not Installed

    Both share the same property set:
        ComputerName, CheckName, Status, RegistryPath,
        ValueName, CurrentValue, Notes, Reference

.NOTES
    Module   : SecurityPosturePS v0.1.0
    See also : https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle

.LINK
    https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/install/installing-windows-powershell

.LINK
    https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    begin {
        $computerName = $env:COMPUTERNAME
        Write-Verbose "[$computerName] Checking installed PowerShell versions..."
    }

    process {
        # ── Windows PowerShell (5.1) ──────────────────────────────────────────
        $wpsRegPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
        $wpsVersion = (Get-ItemProperty -Path $wpsRegPath -Name 'PowerShellVersion' `
                           -ErrorAction SilentlyContinue).PowerShellVersion
        $wpsStatus  = if ($wpsVersion) { 'Installed' } else { 'Not Found' }

        Write-Verbose "[$computerName] Windows PowerShell => $wpsStatus (version: $wpsVersion)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'Windows PowerShell Version'
            Status       = $wpsStatus
            RegistryPath = $wpsRegPath
            ValueName    = 'PowerShellVersion'
            CurrentValue = $wpsVersion
            Notes        = 'Windows PowerShell 5.1 ships with Windows and cannot be removed; the exact build version confirms whether the latest cumulative update has been applied.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/install/installing-windows-powershell'
        }

        # ── PowerShell 7+ (Core) ──────────────────────────────────────────────
        # Each install registers a GUID subkey with a SemanticVersion value.
        $psCoreRegPath  = 'HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions'
        $psCoreVersions = @()

        if (Test-Path -Path $psCoreRegPath) {
            $subKeys = Get-ChildItem -Path $psCoreRegPath -ErrorAction SilentlyContinue
            foreach ($key in $subKeys) {
                $semVer = (Get-ItemProperty -Path $key.PSPath -Name 'SemanticVersion' `
                               -ErrorAction SilentlyContinue).SemanticVersion
                if ($semVer) { $psCoreVersions += $semVer }
            }
        }

        $psCoreStatus = if ($psCoreVersions.Count -gt 0) { 'Installed' } else { 'Not Installed' }
        $psCoreValue  = if ($psCoreVersions.Count -gt 0) { $psCoreVersions -join ', ' } else { $null }

        Write-Verbose "[$computerName] PowerShell 7+ => $psCoreStatus (versions: $psCoreValue)"

        [PSCustomObject]@{
            ComputerName = $computerName
            CheckName    = 'PowerShell 7+ (Core) Installed Versions'
            Status       = $psCoreStatus
            RegistryPath = $psCoreRegPath
            ValueName    = 'SemanticVersion'
            CurrentValue = $psCoreValue
            Notes        = 'PowerShell 7+ is a separately installed side-by-side runtime; end-of-life or stale versions may carry known CVEs and should be updated or uninstalled.'
            Reference    = 'https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows'
        }
    }
}
