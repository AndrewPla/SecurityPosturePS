# Module manifest for SecurityPosturePS
# Generated for v0.1.0

@{
    # Module identity
    RootModule        = 'SecurityPosturePS.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a3f2c891-4d17-4b5e-9c3f-8e1d6a720b44'
    Author            = 'SecurityPosturePS Contributors'
    Description       = 'Audits the security configuration of a Windows machine. Each check returns a pipeline-friendly PSCustomObject with a plain-English Notes field and a Reference URL to the official Microsoft Learn documentation -- so you can understand every result without leaving your terminal.'
    PowerShellVersion = '5.1'

    # Exports — keep explicit so the manifest is the single source of truth
    FunctionsToExport = @(
        # Entry point
        'Get-PSSecurityPosture'

        # PowerShell logging checks
        'Get-PSScriptBlockLogging'
        'Get-PSInvocationLogging'
        'Get-PSModuleLogging'
        'Get-PSTranscription'
        'Get-PSProtectedEventLogging'

        # Execution control checks
        'Get-PSMachineExecutionPolicy'
        'Get-AppLockerScriptRules'

        # Host defense checks
        'Get-WDRealTimeProtection'
        'Get-WinRMPolicy'

        # Event log configuration
        'Get-PSEventLogConfig'
        

        # Event log query tools
        'Get-PSRecentEvents'
        'Get-AppLockerRecentEvents'
        'Get-EventLogClearEvent'

        # Inventory
        'Get-PSVersionInfo'

        # Lab configuration commands
        'Set-PSScriptBlockLogging'
        'Set-PSInvocationLogging'
        'Set-PSModuleLogging'
        'Set-PSTranscription'
        'Set-PSEventLogSize'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Module metadata shown in the PowerShell Gallery / Find-Module
    PrivateData = @{
        PSData = @{
            Tags         = @('Security', 'Audit', 'Hardening', 'Compliance', 'Windows')
            ProjectUri   = 'https://github.com/yourorg/SecurityPosturePS'
            ReleaseNotes = 'Initial release. Includes 10 individual audit functions covering PowerShell logging, execution policy, AppLocker, Windows Defender, WinRM, and PS version inventory. Use Get-PSSecurityPosture to run all checks at once.'
        }
    }
}
