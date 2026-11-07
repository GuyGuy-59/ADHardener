<#
.SYNOPSIS
    Pester tests for the rollback journal (offline: AD cmdlets are stubbed).
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\Journal.psm1'
    $script:TempDir    = Join-Path ([System.IO.Path]::GetTempPath()) "adhardened_journal_test_$(Get-Random)"

    # Stubs visible from the module scope
    function global:Write-Log { param($Message, $Level, $Color) }
    function global:Set-ADObject { param($Identity, $Replace, $Clear, $ProtectedFromAccidentalDeletion, $ErrorAction)
        $global:JournalTestCalls += [PSCustomObject]@{ Identity = $Identity; Replace = $Replace; Clear = $Clear }
    }
    function global:Add-ADGroupMember { param($Identity, $Members, $ErrorAction)
        $global:JournalTestCalls += [PSCustomObject]@{ Identity = $Identity; Members = $Members }
    }

    Import-Module $script:ModulePath -Force
}

AfterAll {
    Remove-Module Journal -Force -ErrorAction SilentlyContinue
    Remove-Item function:global:Write-Log, function:global:Set-ADObject, function:global:Add-ADGroupMember -ErrorAction SilentlyContinue
    Remove-Variable -Name JournalTestCalls -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path $script:TempDir) { Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Module exports' {
    It 'exports the expected functions' {
        $exports = (Get-Module Journal).ExportedFunctions.Keys
        foreach ($name in 'Start-RunJournal', 'Stop-RunJournal', 'Add-JournalEntry', 'Restore-RunJournal',
                          'Get-RunJournalFiles', 'Get-LatestRunJournal', 'Show-RunJournal', 'Get-RunJournalDirectory') {
            $exports | Should -Contain $name
        }
    }
    It 'Restore-RunJournal supports -WhatIf and has ConfirmImpact High' {
        $cmd = Get-Command Restore-RunJournal
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $attr = $cmd.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] }
        $attr.ConfirmImpact | Should -Be 'High'
    }
}

Describe 'Journal lifecycle' {
    It 'Add-JournalEntry is a no-op when no journal is active' {
        { Add-JournalEntry -Type AdAttribute -Data @{ Dn = 'x' } } | Should -Not -Throw
        Get-RunJournalDirectory | Should -BeNullOrEmpty
    }

    It 'creates one file per run and flushes every entry to disk' {
        $path = Start-RunJournal -JournalDirectory $script:TempDir -TargetDomain 'lab.local' -RootDN 'DC=lab,DC=local'
        Test-Path $path | Should -BeTrue
        Get-RunJournalDirectory | Should -Be $script:TempDir

        Add-JournalEntry -Type AdAttribute -Description 'first' -Data @{ Dn = 'DC=lab,DC=local'; Attribute = 'a'; Existed = $true; Kind = 'Int'; OldValue = 10 }
        $j = Get-Content $path -Raw | ConvertFrom-Json
        @($j.Entries).Count | Should -Be 1
        $j.Header.Status | Should -Be 'Running'

        Stop-RunJournal -Status Completed
        $j = Get-Content $path -Raw | ConvertFrom-Json
        $j.Header.Status | Should -Be 'Completed'
        $j.Header.FinishedAt | Should -Not -BeNullOrEmpty
        Get-RunJournalDirectory | Should -BeNullOrEmpty
    }

    It 'two runs in the same second get distinct files' {
        $a = Start-RunJournal -JournalDirectory $script:TempDir
        Stop-RunJournal
        $b = Start-RunJournal -JournalDirectory $script:TempDir
        Stop-RunJournal
        $a | Should -Not -Be $b
    }
}

Describe 'Restore-RunJournal' {
    BeforeEach {
        $global:JournalTestCalls = @()
        $script:dir = Join-Path $script:TempDir "restore_$(Get-Random)"
        $script:file = Start-RunJournal -JournalDirectory $script:dir
        Add-JournalEntry -Type AdAttribute -Description 'one'   -Data @{ Dn = 'DN1'; Attribute = 'ms-DS-MachineAccountQuota'; Existed = $true;  Kind = 'Int'; OldValue = 10 }
        Add-JournalEntry -Type AdAttribute -Description 'two'   -Data @{ Dn = 'DN2'; Attribute = 'dSHeuristics';               Existed = $false; Kind = 'String'; OldValue = $null }
        Add-JournalEntry -Type GroupMember -Description 'three' -Data @{ Group = 'G'; Member = 'M'; Action = 'Removed' }
        Add-JournalEntry -Type Irreversible -Description 'four: recycle bin'
        Stop-RunJournal
    }

    It 'replays entries newest first' {
        $r = Restore-RunJournal -JournalFile $script:file -Confirm:$false
        $global:JournalTestCalls.Count | Should -Be 3
        $global:JournalTestCalls[0].Identity | Should -Be 'G'     # entry 3 first
        $global:JournalTestCalls[1].Identity | Should -Be 'DN2'
        $global:JournalTestCalls[2].Identity | Should -Be 'DN1'
        $r.Restored | Should -Be 3
        $r.Manual   | Should -Be 1
        $r.Failed   | Should -Be 0
    }

    It 'restores the previous value, or clears the attribute when it did not exist' {
        Restore-RunJournal -JournalFile $script:file -Confirm:$false | Out-Null
        ($global:JournalTestCalls | Where-Object Identity -eq 'DN1').Replace['ms-DS-MachineAccountQuota'] | Should -Be 10
        ($global:JournalTestCalls | Where-Object Identity -eq 'DN1').Replace['ms-DS-MachineAccountQuota'] | Should -BeOfType [int]
        ($global:JournalTestCalls | Where-Object Identity -eq 'DN2').Clear | Should -Be 'dSHeuristics'
    }

    It 'marks restored entries and does not replay them a second time' {
        Restore-RunJournal -JournalFile $script:file -Confirm:$false | Out-Null
        $global:JournalTestCalls = @()
        $r = Restore-RunJournal -JournalFile $script:file -Confirm:$false
        $global:JournalTestCalls.Count | Should -Be 0
        $r.Skipped | Should -Be 3
    }

    It '-Force replays entries already restored' {
        Restore-RunJournal -JournalFile $script:file -Confirm:$false | Out-Null
        $global:JournalTestCalls = @()
        Restore-RunJournal -JournalFile $script:file -Confirm:$false -Force | Out-Null
        $global:JournalTestCalls.Count | Should -Be 3
    }

    It '-WhatIf changes nothing and leaves the journal untouched' {
        $before = Get-Content $script:file -Raw
        $r = Restore-RunJournal -JournalFile $script:file -WhatIf
        $global:JournalTestCalls.Count | Should -Be 0
        (Get-Content $script:file -Raw) | Should -Be $before
        $r.Restored | Should -Be 0
    }

    It 'a failing entry does not stop the remaining ones' {
        # Corrupt entry 2 (unknown type) so that it fails
        $j = Get-Content $script:file -Raw | ConvertFrom-Json
        $j.Entries[1].Type = 'DoesNotExist'
        $j | ConvertTo-Json -Depth 12 | Set-Content $script:file -Encoding UTF8
        $r = Restore-RunJournal -JournalFile $script:file -Confirm:$false
        $r.Failed   | Should -Be 1
        $r.Restored | Should -Be 2
    }

    It 'throws when the journal does not exist' {
        { Restore-RunJournal -JournalFile (Join-Path $script:TempDir 'nope.json') -Confirm:$false } | Should -Throw
    }
}

Describe 'Journal discovery' {
    It 'Get-LatestRunJournal returns the most recent file' {
        $dir = Join-Path $script:TempDir "latest_$(Get-Random)"
        $a = Start-RunJournal -JournalDirectory $dir; Stop-RunJournal
        Start-Sleep -Milliseconds 1100
        $b = Start-RunJournal -JournalDirectory $dir; Stop-RunJournal
        (Get-LatestRunJournal -JournalDirectory $dir).FullName | Should -Be $b
        @(Get-RunJournalFiles -JournalDirectory $dir).Count | Should -Be 2
    }
    It 'returns nothing for a missing directory' {
        @(Get-RunJournalFiles -JournalDirectory (Join-Path $script:TempDir 'absent')).Count | Should -Be 0
    }
}
