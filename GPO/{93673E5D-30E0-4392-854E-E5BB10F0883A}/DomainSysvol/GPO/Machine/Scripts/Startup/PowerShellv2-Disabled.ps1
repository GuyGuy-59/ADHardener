<#
.SYNOPSIS
    Startup script: removes the Windows PowerShell 2.0 engine.

.DESCRIPTION
    Deployed by the "PowerShellv2-Disabled" GPO as a computer startup script.
    There is no registry policy that disables PowerShell 2.0, so the GPO removes the feature.
    Idempotent and silent: nothing is done if the feature is absent or already disabled.
    No restart is forced; removal is fully effective after the next reboot.
    Works on Windows client (optional feature) and Windows Server (server feature).
    Result is appended to %ProgramData%\ADHardened\powershellv2.log

    Rationale: PowerShell 2.0 can be started with "powershell -Version 2" to bypass AMSI,
    script block logging and Constrained Language Mode (downgrade attack).
#>
$ErrorActionPreference = 'Stop'
$logDir  = Join-Path $env:ProgramData 'ADHardener'
$logFile = Join-Path $logDir 'powershellv2.log'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }

function Write-FeatureLog([string]$Message) {
    "{0:o} {1}" -f (Get-Date), $Message | Add-Content -Path $logFile -Encoding UTF8
}

try {
    if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
        # Windows Server
        $f = Get-WindowsFeature -Name 'PowerShell-V2' -ErrorAction SilentlyContinue
        if ($f -and $f.Installed) {
            Uninstall-WindowsFeature -Name 'PowerShell-V2' -ErrorAction Stop | Out-Null
            Write-FeatureLog 'Removed server feature PowerShell-V2'
        } else {
            Write-FeatureLog 'Server feature PowerShell-V2 absent or already removed'
        }
    } else {
        # Windows client
        $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction SilentlyContinue
        if ($f -and "$($f.State)" -in 'Enabled', 'EnablePending') {
            Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart -ErrorAction Stop | Out-Null
            Write-FeatureLog 'Disabled optional feature MicrosoftWindowsPowerShellV2Root'
        } else {
            Write-FeatureLog 'Optional feature MicrosoftWindowsPowerShellV2Root absent or already disabled'
        }
    }
} catch {
    Write-FeatureLog "ERROR: $($_.Exception.Message)"
}
