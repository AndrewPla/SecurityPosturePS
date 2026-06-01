function Get-WinRMPolicy {
<#
.SYNOPSIS
    Checks WinRM and PowerShell remoting security posture.

.DESCRIPTION
    Windows Remote Management (WinRM) powers PowerShell Remoting.

    This command checks several practical WinRM posture items:

      - WinRM Group Policy state
      - WinRM service status
      - WinRM service startup type
      - WinRM listener configuration
      - Service AllowUnencrypted
      - Service Basic authentication
      - Service CredSSP authentication
      - Client AllowUnencrypted
      - Client Basic authentication
      - Client TrustedHosts
      - WinRM firewall rules

    This function is read-only.

.EXAMPLE
    Get-WinRMPolicy

.EXAMPLE
    Get-WinRMPolicy | Format-Table CheckName, Status, CurrentValue -AutoSize -Wrap
#>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    function New-WinRMPolicyResult {
        param(
            [Parameter(Mandatory)]
            [string] $CheckName,

            [Parameter(Mandatory)]
            [string] $Status,

            [Parameter()]
            [string] $RegistryPath = 'N/A',

            [Parameter()]
            [string] $ValueName = 'N/A',

            [Parameter()]
            [object] $CurrentValue,

            [Parameter(Mandatory)]
            [string] $Notes,

            [Parameter()]
            [string] $Reference = 'https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements'
        )

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            CheckName    = $CheckName
            Status       = $Status
            RegistryPath = $RegistryPath
            ValueName    = $ValueName
            CurrentValue = $CurrentValue
            Notes        = $Notes
            Reference    = $Reference
        }
    }

    function Get-RegistryValue {
        param(
            [Parameter(Mandatory)]
            [string] $Path,

            [Parameter(Mandatory)]
            [string] $Name
        )

        try {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            $item.$Name
        }
        catch {
            $null
        }
    }

    function Get-WSManSettingValue {
        param(
            [Parameter(Mandatory)]
            [string] $Path
        )

        try {
            $item = Get-Item -Path $Path -ErrorAction Stop
            $item.Value
        }
        catch {
            $null
        }
    }

    function Convert-ToEnabledDisabledStatus {
        param(
            [object] $Value,

            [string] $EnabledStatus = 'Enabled',

            [string] $DisabledStatus = 'Disabled',

            [string] $UnknownStatus = 'Unknown'
        )

        if ($Value -eq $true -or $Value -eq 'true' -or $Value -eq 1 -or $Value -eq '1') {
            return $EnabledStatus
        }

        if ($Value -eq $false -or $Value -eq 'false' -or $Value -eq 0 -or $Value -eq '0') {
            return $DisabledStatus
        }

        $UnknownStatus
    }

    $servicePolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $clientPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'

    $allowAutoConfig = Get-RegistryValue -Path $servicePolicyPath -Name 'AllowAutoConfig'

    $allowAutoConfigStatus = switch ($allowAutoConfig) {
        1 { 'Enabled' }
        0 { 'Disabled' }
        default { 'Not Configured' }
    }

    $resultParams = @{
        CheckName    = 'WinRM Group Policy: Allow remote server management'
        Status       = $allowAutoConfigStatus
        RegistryPath = $servicePolicyPath
        ValueName    = 'AllowAutoConfig'
        CurrentValue = $allowAutoConfig
        Notes        = 'Indicates whether WinRM is enabled by Group Policy. Not Configured does not prove WinRM is disabled because it may have been enabled manually or by another management tool.'
    }
    New-WinRMPolicyResult @resultParams

    $service = Get-Service -Name WinRM -ErrorAction SilentlyContinue

    if ($service) {
        $serviceStatus = if ($service.Status -eq 'Running') { 'Running' } else { 'Stopped' }

        $resultParams = @{
            CheckName    = 'WinRM Service Status'
            Status       = $serviceStatus
            RegistryPath = 'N/A'
            ValueName    = 'WinRM service status'
            CurrentValue = $service.Status
            Notes        = 'Shows whether the WinRM service is currently running. A running service is required for incoming remoting.'
        }
        New-WinRMPolicyResult @resultParams

        $resultParams = @{
            CheckName    = 'WinRM Service Startup Type'
            Status       = [string] $service.StartType
            RegistryPath = 'N/A'
            ValueName    = 'WinRM service start type'
            CurrentValue = $service.StartType
            Notes        = 'Shows how the WinRM service is configured to start. Automatic startup may be expected on managed servers but is worth reviewing on workstations.'
        }
        New-WinRMPolicyResult @resultParams
    }
    else {
        $resultParams = @{
            CheckName    = 'WinRM Service Status'
            Status       = 'Not Found'
            RegistryPath = 'N/A'
            ValueName    = 'WinRM service status'
            CurrentValue = $null
            Notes        = 'The WinRM service was not found on this system.'
        }
        New-WinRMPolicyResult @resultParams
    }

    $listeners = @()

    try {
        $listeners = @(Get-ChildItem -Path 'WSMan:\localhost\Listener' -ErrorAction Stop)
    }
    catch {
        $listeners = @()
    }

    if ($listeners.Count -gt 0) {
        $listenerDetails = foreach ($listener in $listeners) {
            $transportPath = Join-Path -Path $listener.PSPath -ChildPath 'Transport'
            $addressPath = Join-Path -Path $listener.PSPath -ChildPath 'Address'
            $enabledPath = Join-Path -Path $listener.PSPath -ChildPath 'Enabled'

            $transport = Get-WSManSettingValue -Path $transportPath
            $address = Get-WSManSettingValue -Path $addressPath
            $enabled = Get-WSManSettingValue -Path $enabledPath

            [PSCustomObject]@{
                Transport = $transport
                Address   = $address
                Enabled   = $enabled
            }
        }

        $hasHttps = @($listenerDetails | Where-Object { $_.Transport -eq 'HTTPS' }).Count -gt 0
        $listenerStatus = if ($hasHttps) { 'HTTPS Listener Present' } else { 'HTTP Only or Non-HTTPS' }

        $listenerSummary = ($listenerDetails | ForEach-Object {
            "$($_.Transport) on $($_.Address), Enabled=$($_.Enabled)"
        }) -join '; '

        $resultParams = @{
            CheckName    = 'WinRM Listener Configuration'
            Status       = $listenerStatus
            RegistryPath = 'WSMan:\localhost\Listener'
            ValueName    = 'Listener transport and address'
            CurrentValue = $listenerSummary
            Notes        = 'Shows whether WinRM listeners are configured and whether any listener uses HTTPS. HTTP listeners may still use message encryption with Kerberos, but listener configuration should be understood and intentional.'
        }
        New-WinRMPolicyResult @resultParams
    }
    else {
        $resultParams = @{
            CheckName    = 'WinRM Listener Configuration'
            Status       = 'No Listeners'
            RegistryPath = 'WSMan:\localhost\Listener'
            ValueName    = 'Listener transport and address'
            CurrentValue = $null
            Notes        = 'No WinRM listeners were found. This usually means the system is not accepting inbound WinRM connections.'
        }
        New-WinRMPolicyResult @resultParams
    }

    $serviceAllowUnencrypted = Get-WSManSettingValue -Path 'WSMan:\localhost\Service\AllowUnencrypted'
    $serviceAllowUnencryptedStatus = Convert-ToEnabledDisabledStatus -Value $serviceAllowUnencrypted -EnabledStatus 'Risky' -DisabledStatus 'Disabled'

    $resultParams = @{
        CheckName    = 'WinRM Service: AllowUnencrypted'
        Status       = $serviceAllowUnencryptedStatus
        RegistryPath = 'WSMan:\localhost\Service'
        ValueName    = 'AllowUnencrypted'
        CurrentValue = $serviceAllowUnencrypted
        Notes        = 'AllowUnencrypted should generally be false. Enabling it can allow unencrypted WinRM traffic.'
    }
    New-WinRMPolicyResult @resultParams

    $serviceBasic = Get-WSManSettingValue -Path 'WSMan:\localhost\Service\Auth\Basic'
    $serviceBasicStatus = Convert-ToEnabledDisabledStatus -Value $serviceBasic -EnabledStatus 'Risky' -DisabledStatus 'Disabled'

    $resultParams = @{
        CheckName    = 'WinRM Service Auth: Basic'
        Status       = $serviceBasicStatus
        RegistryPath = 'WSMan:\localhost\Service\Auth'
        ValueName    = 'Basic'
        CurrentValue = $serviceBasic
        Notes        = 'Basic authentication should generally be disabled for the WinRM service unless there is a specific, well-controlled reason to allow it.'
    }
    New-WinRMPolicyResult @resultParams

    $serviceCredSSP = Get-WSManSettingValue -Path 'WSMan:\localhost\Service\Auth\CredSSP'
    $serviceCredSSPStatus = Convert-ToEnabledDisabledStatus -Value $serviceCredSSP -EnabledStatus 'Review' -DisabledStatus 'Disabled'

    $resultParams = @{
        CheckName    = 'WinRM Service Auth: CredSSP'
        Status       = $serviceCredSSPStatus
        RegistryPath = 'WSMan:\localhost\Service\Auth'
        ValueName    = 'CredSSP'
        CurrentValue = $serviceCredSSP
        Notes        = 'CredSSP can expose delegated credentials to the remote computer. It should only be enabled when explicitly required and tightly scoped.'
    }
    New-WinRMPolicyResult @resultParams

    $clientAllowUnencrypted = Get-WSManSettingValue -Path 'WSMan:\localhost\Client\AllowUnencrypted'
    $clientAllowUnencryptedStatus = Convert-ToEnabledDisabledStatus -Value $clientAllowUnencrypted -EnabledStatus 'Risky' -DisabledStatus 'Disabled'

    $resultParams = @{
        CheckName    = 'WinRM Client: AllowUnencrypted'
        Status       = $clientAllowUnencryptedStatus
        RegistryPath = 'WSMan:\localhost\Client'
        ValueName    = 'AllowUnencrypted'
        CurrentValue = $clientAllowUnencrypted
        Notes        = 'Client-side AllowUnencrypted should generally be false so outbound WinRM connections do not allow unencrypted communication.'
    }
    New-WinRMPolicyResult @resultParams

    $clientBasic = Get-WSManSettingValue -Path 'WSMan:\localhost\Client\Auth\Basic'
    $clientBasicStatus = Convert-ToEnabledDisabledStatus -Value $clientBasic -EnabledStatus 'Review' -DisabledStatus 'Disabled'

    $resultParams = @{
        CheckName    = 'WinRM Client Auth: Basic'
        Status       = $clientBasicStatus
        RegistryPath = 'WSMan:\localhost\Client\Auth'
        ValueName    = 'Basic'
        CurrentValue = $clientBasic
        Notes        = 'Client-side Basic authentication should be reviewed. If enabled, make sure it is only used with approved management workflows and appropriate transport protection.'
    }
    New-WinRMPolicyResult @resultParams

    $trustedHosts = Get-WSManSettingValue -Path 'WSMan:\localhost\Client\TrustedHosts'

    if ([string]::IsNullOrWhiteSpace([string] $trustedHosts)) {
        $trustedHostsStatus = 'Empty'
    }
    elseif ([string] $trustedHosts -eq '*') {
        $trustedHostsStatus = 'Risky'
    }
    else {
        $trustedHostsStatus = 'Configured'
    }

    $resultParams = @{
        CheckName    = 'WinRM Client TrustedHosts'
        Status       = $trustedHostsStatus
        RegistryPath = 'WSMan:\localhost\Client'
        ValueName    = 'TrustedHosts'
        CurrentValue = $trustedHosts
        Notes        = 'TrustedHosts is used for non-domain or non-Kerberos remoting scenarios. A wildcard value is risky because it trusts any remote host.'
    }
    New-WinRMPolicyResult @resultParams

    $firewallRules = @()

    try {
        $firewallRules = @(Get-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction Stop)
    }
    catch {
        $firewallRules = @()
    }

    if ($firewallRules.Count -gt 0) {
        $enabledRules = @($firewallRules | Where-Object { $_.Enabled -eq 'True' })
        $firewallStatus = if ($enabledRules.Count -gt 0) { 'Enabled Rules Present' } else { 'No Enabled Rules' }

        $firewallValue = ($firewallRules | ForEach-Object {
            "$($_.DisplayName): Enabled=$($_.Enabled), Profile=$($_.Profile)"
        }) -join '; '

        $resultParams = @{
            CheckName    = 'WinRM Firewall Rules'
            Status       = $firewallStatus
            RegistryPath = 'N/A'
            ValueName    = 'Windows Remote Management firewall group'
            CurrentValue = $firewallValue
            Notes        = 'Shows whether Windows Remote Management firewall rules exist and whether any are enabled. Enabled firewall rules can expose WinRM listeners depending on profile and scope.'
        }
        New-WinRMPolicyResult @resultParams
    }
    else {
        $resultParams = @{
            CheckName    = 'WinRM Firewall Rules'
            Status       = 'Not Found'
            RegistryPath = 'N/A'
            ValueName    = 'Windows Remote Management firewall group'
            CurrentValue = $null
            Notes        = 'No Windows Remote Management firewall rules were found or the firewall cmdlets were unavailable.'
        }
        New-WinRMPolicyResult @resultParams
    }
}