<#
.SYNOPSIS
    Pester tests for PSO_config.json (offline).
#>

BeforeAll {
    $script:RepoRoot  = Join-Path $PSScriptRoot '..'
    $script:PsoConfig = Join-Path $script:RepoRoot 'Config\PSO_config.json'
    $script:cfg       = Get-Content -Path $script:PsoConfig -Raw | ConvertFrom-Json
}

Describe 'PSO_config.json' {
    It 'is valid JSON with at least one PSO' {
        @($script:cfg.PSOs).Count | Should -BeGreaterThan 0
    }

    It 'every PSO defines all required settings' {
        $required = 'Name', 'Precedence', 'MinPasswordLength', 'PasswordHistoryCount', 'ComplexityEnabled',
                    'ReversibleEncryptionEnabled', 'MinPasswordAge', 'MaxPasswordAge', 'LockoutThreshold',
                    'LockoutObservationWindow', 'LockoutDuration', 'Subjects'
        foreach ($p in $script:cfg.PSOs) {
            foreach ($k in $required) { $p.PSObject.Properties.Name | Should -Contain $k -Because "$($p.Name) needs $k" }
        }
    }

    It 'names and precedences are unique' {
        $names = @($script:cfg.PSOs.Name); $prec = @($script:cfg.PSOs.Precedence)
        ($names | Select-Object -Unique).Count | Should -Be $names.Count
        ($prec  | Select-Object -Unique).Count | Should -Be $prec.Count
    }

    It 'durations parse and the observation window does not exceed the lockout duration' {
        foreach ($p in $script:cfg.PSOs) {
            $w = [TimeSpan]::Parse($p.LockoutObservationWindow)
            $d = [TimeSpan]::Parse($p.LockoutDuration)
            [TimeSpan]::Parse($p.MinPasswordAge)  | Out-Null
            [TimeSpan]::Parse($p.MaxPasswordAge)  | Out-Null
            $w | Should -BeLessOrEqual $d -Because $p.Name
        }
    }

    It 'enforces at least 12 characters, complexity and no reversible encryption' {
        foreach ($p in $script:cfg.PSOs) {
            $p.MinPasswordLength | Should -BeGreaterOrEqual 12 -Because $p.Name
            $p.ComplexityEnabled | Should -BeTrue -Because $p.Name
            $p.ReversibleEncryptionEnabled | Should -BeFalse -Because $p.Name
        }
    }

    It 'privileged PSOs use at least 15 characters' {
        foreach ($p in $script:cfg.PSOs | Where-Object { $_.Name -match 'Admins' }) {
            $p.MinPasswordLength | Should -BeGreaterOrEqual 15 -Because $p.Name
        }
    }

    It 'every PSO targets at least one group' {
        foreach ($p in $script:cfg.PSOs) { @($p.Subjects).Count | Should -BeGreaterThan 0 -Because $p.Name }
    }
}

Describe 'Global_config.json exposes the PSO function' {
    It 'declares SetFineGrainedPasswordPolicies' {
        $g = Get-Content -Path (Join-Path $script:RepoRoot 'Config\Global_config.json') -Raw | ConvertFrom-Json
        $g.Functions.PSObject.Properties.Name | Should -Contain 'SetFineGrainedPasswordPolicies'
    }
}
