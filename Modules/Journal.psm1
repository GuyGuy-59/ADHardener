<#
.SYNOPSIS
    Single per-run rollback journal for ADHardened.

.DESCRIPTION
    Every run that modifies Active Directory writes ONE JSON file (rollback_<timestamp>.json).
    Each change is appended as an entry holding the information required to undo it
    (previous attribute value, created object, previous ACL, removed group member...).
    The file is flushed after every entry, so it is usable even if the run crashes.

    Restore-RunJournal replays the entries in REVERSE order (last change undone first), which
    guarantees that children are removed before their parents and links before GPOs.
    It replaces the separate per-type backups (state_backup_*, acl_*, preWin2000_members_*).

    Entry types and how they are undone:
      AdAttribute     Set-ADObject back to the previous value (or clear it if it did not exist)
      AdObjectCreated Remove the object (OU, group, authentication policy / silo) if it has no children
      AdAcl           Restore the previous security descriptor (SDDL)
      GroupMember     Re-add a member removed from a group
      AccountNotDelegated  Restore the previous flag
      GpoImport       Remove the GPO if it was created, otherwise re-import its pre-run backup
      GpoLink         Remove the GPO link
      Pso             Remove the PSO if it was created, otherwise restore its previous settings
      PsoSubject      Remove the PSO subject
      SiloMember      Clear the silo / policy assignment of the account and revoke access
      Irreversible    Cannot be undone (AD Recycle Bin, schema extension...): reported only

    Add-JournalEntry is a no-op when no journal is active, so the hardening functions keep
    working when called on their own.

    Functions exported:
      - Start-RunJournal / Stop-RunJournal
      - Add-JournalEntry
      - Get-RunJournalDirectory
      - Get-RunJournalFiles / Get-LatestRunJournal
      - Show-RunJournal
      - Restore-RunJournal
#>

$script:RunJournal = $null

function Write-JournalFile {
    # Each entry is serialized ONCE (cached in Json) and the file is assembled by string concatenation,
    # so a run with hundreds of entries does not re-serialize the whole journal after every change.
    [CmdletBinding()]
    param()
    if (-not $script:RunJournal) { return }
    $header  = $script:RunJournal.Header | ConvertTo-Json -Depth 5
    $entries = $script:RunJournal.Json -join ",`n"
    $text = "{`n`"Header`": $header,`n`"Entries`": [`n$entries`n]`n}"
    Set-Content -Path $script:RunJournal.Path -Value $text -Encoding UTF8 -WhatIf:$false -Confirm:$false
}

function Start-RunJournal {
    <#
    .SYNOPSIS Open a new journal file for the current run and make it the active journal.
    .OUTPUTS  Path of the journal file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$JournalDirectory,
        [Parameter()] [string]$TargetDomain,
        [Parameter()] [string]$RootDN
    )

    if (-not (Test-Path $JournalDirectory)) {
        New-Item -ItemType Directory -Path $JournalDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path = Join-Path $JournalDirectory "rollback_${timestamp}.json"
    # Two runs in the same second must not share a file
    $i = 1
    while (Test-Path $path) { $path = Join-Path $JournalDirectory "rollback_${timestamp}_$i.json"; $i++ }

    $script:RunJournal = @{
        Path      = $path
        Directory = $JournalDirectory
        Stamp     = $timestamp
        Header    = [ordered]@{
            Id           = [guid]::NewGuid().ToString()
            StartedAt    = (Get-Date -Format 'o')
            FinishedAt   = $null
            Status       = 'Running'
            TargetDomain = $TargetDomain
            RootDN       = $RootDN
            User         = "$env:USERDOMAIN\$env:USERNAME"
            Computer     = $env:COMPUTERNAME
        }
        Entries   = [System.Collections.Generic.List[object]]::new()
        Json      = [System.Collections.Generic.List[string]]::new()
    }
    Write-JournalFile
    Write-Log "Rollback journal: $path" -Level INFO
    return $path
}

function Stop-RunJournal {
    [CmdletBinding()]
    param([ValidateSet('Completed', 'Failed')] [string]$Status = 'Completed')

    if (-not $script:RunJournal) { return }
    $script:RunJournal.Header.FinishedAt = (Get-Date -Format 'o')
    $script:RunJournal.Header.Status     = $Status
    Write-JournalFile
    $count = $script:RunJournal.Entries.Count
    $path  = $script:RunJournal.Path
    $script:RunJournal = $null
    Write-Log "Rollback journal closed ($count entr$(if ($count -eq 1) { 'y' } else { 'ies' })): $path" -Level INFO
}

function Add-JournalEntry {
    <#
    .SYNOPSIS Append one undoable change to the active journal (no-op if none is active).
    .PARAMETER Type        One of the entry types listed in the module header.
    .PARAMETER Description Human readable description, shown in Show-RunJournal.
    .PARAMETER Data        Hashtable with the type-specific fields needed to undo the change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Type,
        [Parameter()] [string]$Description = '',
        [Parameter()] [hashtable]$Data = @{}
    )
    if (-not $script:RunJournal) { return }
    $entry = [ordered]@{
        Seq         = $script:RunJournal.Entries.Count + 1
        Time        = (Get-Date -Format 'o')
        Type        = $Type
        Description = $Description
        Data        = $Data
    }
    $script:RunJournal.Entries.Add($entry)
    $script:RunJournal.Json.Add(($entry | ConvertTo-Json -Depth 12 -Compress))
    Write-JournalFile
}

function Get-RunJournalDirectory {
    <# Directory of the active journal (used to store pre-change artefacts such as GPO backups), or $null. #>
    [CmdletBinding()]
    param()
    if ($script:RunJournal) { return $script:RunJournal.Directory }
    return $null
}

function Get-RunJournalFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$JournalDirectory)
    if (-not (Test-Path $JournalDirectory)) { return @() }
    return @(Get-ChildItem -Path $JournalDirectory -Filter 'rollback_*.json' -File -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending)
}

function Get-LatestRunJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$JournalDirectory)
    return Get-RunJournalFiles -JournalDirectory $JournalDirectory | Select-Object -First 1
}

function Format-JournalEntry {
    param($Entry)
    if ($Entry.Description) { return $Entry.Description }
    $d = $Entry.Data
    switch ($Entry.Type) {
        'AdAttribute'     { "Attribute $($d.Attribute) of $($d.Dn)" }
        'AdObjectCreated' { "Created $($d.ObjectClass) $($d.Dn)" }
        'AdAcl'           { "ACL of $($d.Dn)" }
        'GroupMember'     { "Member $($d.Member) of $($d.Group)" }
        'GpoImport'       { "GPO $($d.GpoName)" }
        'GpoLink'         { "Link $($d.GpoName) -> $($d.Target)" }
        'Pso'             { "PSO $($d.Name)" }
        'PsoSubject'      { "PSO $($d.Pso) subject $($d.Subject)" }
        'SiloMember'      { "Silo assignment of $($d.Sam)" }
        default           { $Entry.Type }
    }
}

function Show-RunJournal {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string]$JournalFile)

    if (-not (Test-Path $JournalFile)) {
        Write-Log "Journal not found: $JournalFile" -Level ERROR
        return
    }
    $j = Get-Content -Path $JournalFile -Raw | ConvertFrom-Json
    Write-Log "`n=== Rollback journal: $(Split-Path $JournalFile -Leaf) ===" -Level INFO -Color Cyan
    Write-Log "Started : $($j.Header.StartedAt)  by $($j.Header.User) on $($j.Header.Computer)" -Level INFO
    Write-Log "Status  : $($j.Header.Status)    Domain: $($j.Header.TargetDomain)" -Level INFO
    $entries = @($j.Entries)
    Write-Log "Entries : $($entries.Count)" -Level INFO
    foreach ($e in $entries) {
        $mark = if ($e.RestoredAt) { '[restored]' } elseif ($e.Type -eq 'Irreversible') { '[manual]  ' } else { '[pending] ' }
        Write-Log ("  {0} #{1,-3} {2,-16} {3}" -f $mark, $e.Seq, $e.Type, (Format-JournalEntry $e)) -Level INFO
    }
}

# =============================================================================
# Undo handlers (one per entry type)
# =============================================================================

function ConvertTo-JournalValue {
    param($Value, [string]$Kind)
    switch ($Kind) {
        'Int'     { return [int]$Value }
        'Strings' { return [string[]]@($Value) }
        default   { return [string]$Value }
    }
}

function Invoke-JournalUndo {
    <# Applies the inverse of one entry. Throws on failure. Returns a short result string. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Entry)

    $d = $Entry.Data
    switch ($Entry.Type) {

        'AdAttribute' {
            if ($d.Existed) {
                $value = ConvertTo-JournalValue -Value $d.OldValue -Kind $d.Kind
                Set-ADObject -Identity $d.Dn -Replace @{ $d.Attribute = $value } -ErrorAction Stop
                return "restored $($d.Attribute)"
            }
            Set-ADObject -Identity $d.Dn -Clear $d.Attribute -ErrorAction Stop
            return "cleared $($d.Attribute)"
        }

        'AdObjectCreated' {
            $obj = Get-ADObject -Identity $d.Dn -ErrorAction SilentlyContinue
            if (-not $obj) { return 'already absent' }
            $children = @(Get-ADObject -SearchBase $d.Dn -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue)
            if ($children.Count -gt 0) {
                throw "not removed: $($children.Count) child object(s) present under $($d.Dn)"
            }
            Set-ADObject -Identity $d.Dn -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
            Remove-ADObject -Identity $d.Dn -Confirm:$false -ErrorAction Stop
            return 'object removed'
        }

        'AdAcl' {
            $acl = Get-Acl -Path "AD:$($d.Dn)" -ErrorAction Stop
            $acl.SetSecurityDescriptorSddlForm($d.Sddl, [System.Security.AccessControl.AccessControlSections]::Access)
            Set-Acl -Path "AD:$($d.Dn)" -AclObject $acl -ErrorAction Stop
            return 'ACL restored'
        }

        'GroupMember' {
            Add-ADGroupMember -Identity $d.Group -Members $d.Member -ErrorAction Stop
            return 'member re-added'
        }

        'AccountNotDelegated' {
            Set-ADUser -Identity $d.Dn -AccountNotDelegated ([bool]$d.OldValue) -ErrorAction Stop
            return "AccountNotDelegated = $($d.OldValue)"
        }

        'GpoImport' {
            if ($d.Created) {
                Remove-GPO -Name $d.GpoName -Domain $d.Domain -ErrorAction Stop
                return 'GPO removed'
            }
            if ($d.BackupId -and $d.BackupPath) {
                Import-GPO -BackupId $d.BackupId -Path $d.BackupPath -TargetName $d.GpoName -Domain $d.Domain -ErrorAction Stop | Out-Null
                return 'previous GPO content re-imported'
            }
            throw 'GPO existed before the run and no pre-import backup was recorded'
        }

        'GpoLink' {
            Remove-GPLink -Name $d.GpoName -Target $d.Target -Domain $d.Domain -ErrorAction Stop | Out-Null
            return 'link removed'
        }

        'Pso' {
            if ($d.Created) {
                # Created with ProtectedFromAccidentalDeletion: must be lifted before removal
                Set-ADObject -Identity (Get-ADFineGrainedPasswordPolicy -Identity $d.Name -ErrorAction Stop).DistinguishedName `
                    -ProtectedFromAccidentalDeletion $false -ErrorAction SilentlyContinue
                Remove-ADFineGrainedPasswordPolicy -Identity $d.Name -Confirm:$false -ErrorAction Stop
                return 'PSO removed'
            }
            $o = $d.Old
            Set-ADFineGrainedPasswordPolicy -Identity $d.Name `
                -Precedence ([int]$o.Precedence) `
                -ComplexityEnabled ([bool]$o.ComplexityEnabled) `
                -ReversibleEncryptionEnabled ([bool]$o.ReversibleEncryptionEnabled) `
                -LockoutThreshold ([int]$o.LockoutThreshold) `
                -LockoutDuration ([TimeSpan]::Parse($o.LockoutDuration)) `
                -LockoutObservationWindow ([TimeSpan]::Parse($o.LockoutObservationWindow)) `
                -MinPasswordLength ([int]$o.MinPasswordLength) `
                -PasswordHistoryCount ([int]$o.PasswordHistoryCount) `
                -MinPasswordAge ([TimeSpan]::Parse($o.MinPasswordAge)) `
                -MaxPasswordAge ([TimeSpan]::Parse($o.MaxPasswordAge)) `
                -ErrorAction Stop
            return 'previous PSO settings restored'
        }

        'PsoSubject' {
            Remove-ADFineGrainedPasswordPolicySubject -Identity $d.Pso -Subjects $d.Subject -Confirm:$false -ErrorAction Stop
            return 'subject removed'
        }

        'SiloMember' {
            Set-ADObject -Identity $d.Dn -Clear 'msDS-AssignedAuthNPolicySilo', 'msDS-AssignedAuthNPolicy' -ErrorAction Stop
            if ($d.Silo -and $d.Sam) {
                Revoke-ADAuthenticationPolicySiloAccess -Identity $d.Silo -Account $d.Sam -Confirm:$false -ErrorAction SilentlyContinue
            }
            return 'silo assignment cleared'
        }

        'Irreversible' { throw 'cannot be undone automatically' }

        default { throw "Unknown journal entry type: $($Entry.Type)" }
    }
}

function Restore-RunJournal {
    <#
    .SYNOPSIS Undo the changes recorded in a rollback journal, newest first (best-effort).
    .DESCRIPTION
        Replays the journal in reverse order. A failing entry is reported and skipped; the
        remaining entries are still processed. Entries already restored are skipped unless
        -Force is given. Use -WhatIf to preview. The journal file is updated with a
        RestoredAt marker on every entry that was undone.
        AD operations are not transactional: keep a system-state backup of every DC.
    .PARAMETER JournalFile  Path of a rollback_*.json file.
    .PARAMETER Force        Replay entries even if already marked as restored.
    .OUTPUTS  PSCustomObject with Restored / Failed / Skipped / Manual counts.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [string]$JournalFile,
        [switch]$Force
    )

    if (-not (Test-Path $JournalFile)) { throw "Journal not found: $JournalFile" }
    $journal = Get-Content -Path $JournalFile -Raw | ConvertFrom-Json
    $entries = @($journal.Entries)

    Write-Log "`n=== Restoring from journal: $(Split-Path $JournalFile -Leaf) ===" -Level INFO -Color Cyan
    Write-Log "Run started : $($journal.Header.StartedAt)  ($($journal.Header.Status))" -Level INFO
    Write-Log "Entries     : $($entries.Count) (replayed newest first)" -Level INFO

    $result = [PSCustomObject]@{ Restored = 0; Failed = 0; Skipped = 0; Manual = 0 }

    # One confirmation for the whole journal (not one per entry); -WhatIf previews every entry
    $preview = [bool]$WhatIfPreference
    $pending = @($entries | Where-Object { $_.Type -ne 'Irreversible' -and ($Force -or -not $_.RestoredAt) }).Count
    if (-not $preview -and -not $PSCmdlet.ShouldProcess((Split-Path $JournalFile -Leaf), "Undo $pending change(s), newest first")) {
        $result.Skipped = $entries.Count
        return $result
    }
    $reversed = @($entries | Sort-Object { [int]$_.Seq } -Descending)

    foreach ($e in $reversed) {
        $label = "#$($e.Seq) $($e.Type) - $(Format-JournalEntry $e)"

        if ($e.Type -eq 'Irreversible') {
            Write-Log "  [!] Manual action required: $label" -Level WARN
            $result.Manual++
            continue
        }
        if ($e.RestoredAt -and -not $Force) {
            Write-Log "  [=] Already restored: $label" -Level DEBUG
            $result.Skipped++
            continue
        }

        if ($preview) {
            Write-Log "  [WhatIf] Would undo: $label" -Level INFO
            $result.Skipped++
            continue
        }

        try {
            $msg = Invoke-JournalUndo -Entry $e
            Write-Log "  [OK] $label : $msg" -Level SUCCESS
            $e | Add-Member -NotePropertyName RestoredAt -NotePropertyValue (Get-Date -Format 'o') -Force
            $result.Restored++
        } catch {
            Write-Log "  [X] $label : $($_.Exception.Message)" -Level ERROR
            $result.Failed++
        }
    }

    if ($result.Restored -gt 0) {
        $journal | ConvertTo-Json -Depth 12 | Set-Content -Path $JournalFile -Encoding UTF8 -WhatIf:$false -Confirm:$false
    }

    Write-Log "`nRestore summary: restored=$($result.Restored) failed=$($result.Failed) skipped=$($result.Skipped) manual=$($result.Manual)" -Level INFO
    return $result
}

Export-ModuleMember -Function `
    Start-RunJournal, Stop-RunJournal, Add-JournalEntry, Get-RunJournalDirectory, `
    Get-RunJournalFiles, Get-LatestRunJournal, Show-RunJournal, Restore-RunJournal
