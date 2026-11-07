<#
.SYNOPSIS
    Pester tests for the hardening report (offline portions: scoring, HTML/CSV/JSON export).
#>

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\Modules\Reporting.psm1'
    $script:TempDir    = Join-Path ([System.IO.Path]::GetTempPath()) "adhardened_report_test_$(Get-Random)"
    function global:Write-Log { param($Message, $Level, $Color) }
    Import-Module $script:ModulePath -Force

    function New-Result($Category, $Status) {
        [PSCustomObject]@{ Id = "$Category-$Status"; Category = $Category; Control = 'c'; Status = $Status; ConfiguredToApply = $false; Details = ''; Remediation = '' }
    }
}

AfterAll {
    Remove-Module Reporting -Force -ErrorAction SilentlyContinue
    Remove-Item function:global:Write-Log -ErrorAction SilentlyContinue
    if (Test-Path $script:TempDir) { Remove-Item -Path $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Module exports' {
    It 'exports the expected functions' {
        $exports = (Get-Module Reporting).ExportedFunctions.Keys
        foreach ($name in 'Get-HardeningReport', 'Get-HardeningScore', 'Export-HardeningReport', 'Show-HardeningReport', 'ConvertTo-HardeningHtml') {
            $exports | Should -Contain $name
        }
    }
}

Describe 'Get-HardeningScore' {
    It 'computes compliant / (compliant + non-compliant)' {
        $r = @(
            (New-Result 'A' 'Compliant'), (New-Result 'A' 'Compliant'), (New-Result 'A' 'Compliant'), (New-Result 'A' 'NonCompliant')
        )
        (Get-HardeningScore -Results $r).Score | Should -Be 75
    }

    It 'excludes NotApplicable and Error from the score' {
        $r = @(
            (New-Result 'A' 'Compliant'), (New-Result 'A' 'NonCompliant'),
            (New-Result 'A' 'NotApplicable'), (New-Result 'A' 'Error')
        )
        $s = Get-HardeningScore -Results $r
        $s.Score         | Should -Be 50
        $s.NotApplicable | Should -Be 1
        $s.Error         | Should -Be 1
        $s.Total         | Should -Be 4
    }

    It 'scores each category independently' {
        $r = @(
            (New-Result 'GPO' 'Compliant'), (New-Result 'GPO' 'Compliant'),
            (New-Result 'PSO' 'NonCompliant'), (New-Result 'PSO' 'Compliant')
        )
        $s = Get-HardeningScore -Results $r
        ($s.Categories | Where-Object Category -eq 'GPO').Score | Should -Be 100
        ($s.Categories | Where-Object Category -eq 'PSO').Score | Should -Be 50
        $s.Score | Should -Be 75
    }

    It 'returns a null score when nothing can be evaluated' {
        (Get-HardeningScore -Results @((New-Result 'A' 'NotApplicable'))).Score | Should -BeNullOrEmpty
        (Get-HardeningScore -Results @()).Total | Should -Be 0
    }
}

Describe 'Export-HardeningReport' {
    It 'writes a CSV with one line per control and a JSON with the score' {
        $r = @((New-Result 'GPO' 'Compliant'), (New-Result 'GPO' 'NonCompliant'))
        $files = Export-HardeningReport -Results $r -OutputDirectory (Join-Path $script:TempDir 'out') -TargetDomain 'lab.local'
        @(Import-Csv $files.Csv).Count | Should -Be 2
        (Import-Csv $files.Csv)[0].PSObject.Properties.Name | Should -Contain 'Status'
        $json = Get-Content $files.Json -Raw | ConvertFrom-Json
        $json.Score.Score | Should -Be 50
        $json.TargetDomain | Should -Be 'lab.local'
    }
}

Describe 'Invoke-HardeningCheck outcome handling' {
    It 'reports Error (not an exception) when a check throws' {
        InModuleScope Reporting {
            $r = Invoke-HardeningCheck -Id 'T1' -Category 'x' -Control 'boom' -Test { throw 'ad unreachable' }
            $r.Status  | Should -Be 'Error'
            $r.Details | Should -Match 'ad unreachable'
        }
    }
    It 'only proposes a remediation when non-compliant' {
        InModuleScope Reporting {
            $ko = Invoke-HardeningCheck -Id 'T2' -Category 'x' -Control 'c' -Remediation 'fix it' -Test { New-CheckOutcome $false 'd' }
            $ok = Invoke-HardeningCheck -Id 'T3' -Category 'x' -Control 'c' -Remediation 'fix it' -Test { New-CheckOutcome $true 'd' }
            $ko.Remediation | Should -Be 'fix it'
            $ok.Remediation | Should -BeNullOrEmpty
        }
    }
    It 'reports whether the function is enabled in the configuration' {
        InModuleScope Reporting {
            $cfg = [PSCustomObject]@{ SetThing = $true }
            (Invoke-HardeningCheck -Id 'T4' -Category 'x' -Control 'c' -FunctionKey 'SetThing' -EnabledFunctions $cfg -Test { New-CheckOutcome $true }).ConfiguredToApply | Should -BeTrue
        }
    }
}

Describe 'ConvertTo-HardeningHtml' {
    BeforeAll {
        $script:res = @(
            [PSCustomObject]@{ Id = 'AD-03'; Category = 'Domain hardening'; Control = 'MAQ = 0'; Status = 'NonCompliant'; ConfiguredToApply = $true;  Details = 'quota = 10'; Remediation = "Enable 'X'" }
            [PSCustomObject]@{ Id = 'AD-01'; Category = 'Domain hardening'; Control = 'Bind';   Status = 'Compliant';    ConfiguredToApply = $false; Details = 'ok';         Remediation = '' }
        )
        $script:html = ConvertTo-HardeningHtml -Results $script:res -TargetDomain 'lab.local' -GeneratedAt '2026-01-01 10:00'
    }
    It 'is a complete, self-contained page' {
        $script:html | Should -Match '^<!doctype html>'
        $script:html | Should -Match '</html>\s*$'
        $script:html | Should -Not -Match 'https?://'          # no external resource
        $script:html | Should -Not -Match '__[A-Z]+__'         # every placeholder replaced
    }
    It 'shows the score, domain and one row per control' {
        $script:html | Should -Match 'class="big warn">50<small>'
        $script:html | Should -Match 'lab\.local'
        ([regex]::Matches($script:html, '<tr data-status=')).Count | Should -Be 2
    }
    It 'lists non-compliant controls first and shows the remediation' {
        $script:html.IndexOf('AD-03') | Should -BeLessThan $script:html.IndexOf('AD-01')
        $script:html | Should -Match 'Fix: Enable &#39;X&#39;'
    }
    It 'HTML-encodes every value (no injection)' {
        $evil = @([PSCustomObject]@{ Id = '<script>alert(1)</script>'; Category = 'c'; Control = '"><img src=x>'; Status = 'Error'; ConfiguredToApply = $false; Details = '<b>'; Remediation = '' })
        $h = ConvertTo-HardeningHtml -Results $evil -TargetDomain '<i>d</i>'
        $h | Should -Not -Match '<script>alert'
        $h | Should -Not -Match '<img src=x>'
        $h | Should -Match '&lt;script&gt;alert'
    }
    It 'handles an empty result list (score n/a)' {
        $h = ConvertTo-HardeningHtml -Results @()
        $h | Should -Match 'class="big na">n/a<small>'
    }
    It 'Export-HardeningReport also writes the HTML file' {
        $f = Export-HardeningReport -Results $script:res -OutputDirectory (Join-Path $script:TempDir 'out2') -TargetDomain 'lab.local'
        Test-Path $f.Html | Should -BeTrue
        $f.Html | Should -Match '\.html$'
    }
}
