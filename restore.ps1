<#
.SYNOPSIS
    Interactive rollback tool for Sec_AD changes.

.DESCRIPTION
    Restores the changes made by ADHardened. The recommended way is the rollback journal:
    every run writes ONE file backups\journal\rollback_<timestamp>.json, and -JournalFile /
    -LastJournal replays it in reverse order (newest change undone first).
    The former per-type backups (state, ACL, Pre-Windows 2000) are still supported.
    Always supports -WhatIf.

.PARAMETER JournalFile
    Path to a rollback_*.json journal to restore (all entries, newest first).

.PARAMETER LastJournal
    Restore the most recent journal.

.PARAMETER ShowJournal
    Display the content of the journal selected by -JournalFile / -LastJournal and exit.

.PARAMETER Force
    With a journal: replay entries even if they are already marked as restored.

.PARAMETER List
    Just list available backups and exit.

.PARAMETER StateBackupFile
    Path to a state_backup_*.json to restore. Use with -All or specific -Include* switches.

.PARAMETER ACLBackupFile
    Path to an acl_*.json to restore.

.PARAMETER PreWin2000BackupFile
    Path to a preWin2000_members_*.json to restore.

.PARAMETER All
    When restoring a state backup, restore all categories (domain attrs, GPO links, groups, OUs).

.EXAMPLE
    .\restore.ps1 -List
    Show available journals and backups.

.EXAMPLE
    .\restore.ps1 -LastJournal -WhatIf
    Preview the undo of the last run.

.EXAMPLE
    .\restore.ps1 -JournalFile .\backups\journal\rollback_20260510_213601.json
    Undo that run, newest change first.

.EXAMPLE
    .\restore.ps1 -StateBackupFile .\backups\state_backup_20260510_213601.json -All -WhatIf
    Preview a full state restore.

.EXAMPLE
    .\restore.ps1 -ACLBackupFile .\backups\acl\acl_OU_Tier0_DC_lab_DC_local_20260510_215000.json
    Restore an OU's ACL (will prompt for confirmation due to ConfirmImpact=High).

.NOTES
    AD operations are not transactional. This is a best-effort tool intended for staged
    deployments and lab environments. Always have a separate full system-state backup
    of every Domain Controller.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()] [switch]$List,

    [Parameter()] [string]$JournalFile,
    [Parameter()] [switch]$LastJournal,
    [Parameter()] [switch]$ShowJournal,
    [Parameter()] [switch]$Force,

    [Parameter()] [string]$StateBackupFile,
    [Parameter()] [string]$ACLBackupFile,
    [Parameter()] [string]$PreWin2000BackupFile,

    [Parameter()] [switch]$All,
    [Parameter()] [switch]$IncludeDomainAttrs,
    [Parameter()] [switch]$IncludeOUs,
    [Parameter()] [switch]$IncludeGroups,
    [Parameter()] [switch]$IncludeGPOLinks,
    [Parameter()] [switch]$IncludeAccountDelegation,
    [Parameter()] [switch]$IncludeSilos,
    [Parameter()] [switch]$IncludePrivilegedGroups,

    [Parameter()] [string]$BackupDirectory
)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $BackupDirectory) {
    $BackupDirectory = Join-Path $scriptPath 'backups'
}

# Load required modules
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy     -ErrorAction Stop

$customModules = @('Logging.psm1', 'Journal.psm1', 'StateManagement.psm1')
foreach ($m in $customModules) {
    $path = Join-Path $scriptPath "Modules\$m"
    if (-not (Test-Path $path)) {
        Write-Error "Module missing: $path"
        exit 1
    }
    if (Get-Module -Name ([System.IO.Path]::GetFileNameWithoutExtension($m))) {
        Remove-Module ([System.IO.Path]::GetFileNameWithoutExtension($m)) -Force
    }
    Import-Module $path -Force
}

# Init logging
$logDir = Join-Path $scriptPath 'logs'
Initialize-Logging -LogDirectory $logDir -Prefix 'restore' | Out-Null
Write-Log 'Sec_AD restore started' -Level INFO -Color Cyan

# --- List mode ---
$journalDir = Join-Path $BackupDirectory 'journal'

if ($List) {
    $journals = Get-RunJournalFiles -JournalDirectory $journalDir
    Write-Host "`n=== Rollback journals in $journalDir ===" -ForegroundColor Cyan
    Write-Host "`nRun journals ($($journals.Count)) - restore with -JournalFile <path> or -LastJournal:" -ForegroundColor Yellow
    foreach ($f in $journals) {
        Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $f.Name, $f.LastWriteTime)
    }

    $backups = Get-AvailableBackups -BackupDirectory $BackupDirectory
    Write-Host "`n=== Legacy backups in $BackupDirectory ===" -ForegroundColor Cyan

    Write-Host "`nState baselines ($($backups.State.Count)):" -ForegroundColor Yellow
    foreach ($f in $backups.State) {
        Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $f.Name, $f.LastWriteTime)
    }
    Write-Host "`nOU ACL backups ($($backups.ACL.Count)):" -ForegroundColor Yellow
    foreach ($f in $backups.ACL) {
        Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $f.Name, $f.LastWriteTime)
    }
    Write-Host "`nPre-Windows 2000 backups ($($backups.PreWin2000.Count)):" -ForegroundColor Yellow
    foreach ($f in $backups.PreWin2000) {
        Write-Host ("  {0}  ({1:yyyy-MM-dd HH:mm})" -f $f.Name, $f.LastWriteTime)
    }
    Write-Host ''
    return
}

# --- Restore actions ---
$didSomething = $false

if ($LastJournal -and -not $JournalFile) {
    $latest = Get-LatestRunJournal -JournalDirectory $journalDir
    if (-not $latest) { Write-Host "No journal found in $journalDir" -ForegroundColor Red; exit 1 }
    $JournalFile = $latest.FullName
}

if ($JournalFile) {
    $didSomething = $true
    if ($ShowJournal) {
        Show-RunJournal -JournalFile $JournalFile
    } else {
        Show-RunJournal -JournalFile $JournalFile
        $params = @{ JournalFile = $JournalFile }
        if ($Force)            { $params.Force = $true }
        if ($WhatIfPreference) { $params.WhatIf = $true }
        $summary = Restore-RunJournal @params
        if ($summary -and $summary.Failed -gt 0) {
            Write-Log "Some entries could not be restored (see above)." -Level WARN
        }
    }
}

if ($StateBackupFile) {
    $didSomething = $true
    Write-Log "Restoring state baseline: $StateBackupFile" -Level INFO

    # Show diff first
    $diff = Compare-StateBackup -BackupFile $StateBackupFile
    Write-Host "`n--- Preview of changes ---" -ForegroundColor Cyan
    Write-Host "Domain attributes    : $($diff.DomainAttrs.Count)"
    Write-Host "OUs to delete        : $($diff.OUsToDelete.Count)"
    Write-Host "Groups to delete     : $($diff.GroupsToDelete.Count)"
    Write-Host "Links to remove      : $($diff.LinksToRemove.Count)"
    Write-Host "Links to re-add      : $($diff.LinksToReadd.Count)"
    Write-Host "AccountDelegation    : $($diff.AccountDelegationChanges.Count)"
    Write-Host "Silos to delete      : $($diff.SilosToDelete.Count)"
    Write-Host "Priv members remove  : $($diff.PrivGroupMembersToRemove.Count)"
    Write-Host "Priv members re-add  : $($diff.PrivGroupMembersToReadd.Count)"
    Write-Host ''

    $params = @{ BackupFile = $StateBackupFile }
    if ($All)                      { $params.All = $true }
    if ($IncludeDomainAttrs)       { $params.IncludeDomainAttrs = $true }
    if ($IncludeOUs)               { $params.IncludeOUs = $true }
    if ($IncludeGroups)            { $params.IncludeGroups = $true }
    if ($IncludeGPOLinks)          { $params.IncludeGPOLinks = $true }
    if ($IncludeAccountDelegation) { $params.IncludeAccountDelegation = $true }
    if ($IncludeSilos)             { $params.IncludeSilos = $true }
    if ($IncludePrivilegedGroups)  { $params.IncludePrivilegedGroups = $true }
    if ($WhatIfPreference)         { $params.WhatIf = $true }

    Restore-StateBackup @params
}

if ($ACLBackupFile) {
    $didSomething = $true
    $params = @{ BackupFile = $ACLBackupFile }
    if ($WhatIfPreference) { $params.WhatIf = $true }
    Restore-OUSecurityDescriptor @params
}

if ($PreWin2000BackupFile) {
    $didSomething = $true
    $params = @{ BackupFile = $PreWin2000BackupFile }
    if ($WhatIfPreference) { $params.WhatIf = $true }
    Restore-PreWindows2000Members @params
}

if (-not $didSomething) {
    Write-Host "`nNo action specified. Use -List to see backups, or specify a backup file." -ForegroundColor Yellow
    Write-Host "Examples:" -ForegroundColor Gray
    Write-Host "  .\restore.ps1 -List" -ForegroundColor Gray
    Write-Host "  .\restore.ps1 -LastJournal -WhatIf" -ForegroundColor Gray
    Write-Host "  .\restore.ps1 -JournalFile <path>" -ForegroundColor Gray
    Write-Host "  .\restore.ps1 -StateBackupFile <path> -All -WhatIf" -ForegroundColor Gray
    Write-Host "  .\restore.ps1 -ACLBackupFile <path>" -ForegroundColor Gray
    exit 1
}

Write-Log "Restore finished. Log: $(Get-LogFilePath)" -Level SUCCESS
