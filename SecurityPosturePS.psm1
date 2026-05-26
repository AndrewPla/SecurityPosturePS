# SecurityPosturePS.psm1
# Dot-sources all public functions from the Public\ folder.
# Add a Private\ folder and dot-source it here when internal helpers are needed.

$publicFunctions = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue

foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
        Write-Verbose "Imported: $($function.Name)"
    }
    catch {
        Write-Error "Failed to import $($function.FullName): $_"
    }
}

# Export all functions defined by the dot-sourced files.
# The manifest's FunctionsToExport is the authoritative allow-list;
# this wildcard simply avoids maintaining a duplicate list here.
Export-ModuleMember -Function '*'
