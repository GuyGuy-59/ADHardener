<#
.SYNOPSIS
    Pester tests for the network baseline GPOs (Firewall, WinRM server/client, PowerShell 2.0)
    and for Get-GpoBackupInfo. Reads the real backups of the GPO\ folder (offline).
#>

BeforeAll {
    $script:RepoRoot = Join-Path $PSScriptRoot '..'
    $script:GpoDir   = Join-Path $script:RepoRoot 'GPO'
    function global:Write-Log { param($Message, $Level, $Color) }
    Import-Module (Join-Path $script:RepoRoot 'Modules\GPO.psm1') -Force -DisableNameChecking

    # Minimal reader of registry.pol (PReg format): returns @{ 'key|name' = value }
    function Read-RegistryPol {
        param([string]$Path)
        $b = [System.IO.File]::ReadAllBytes($Path)
        $st = @{ I = 8 }                       # shared cursor (a nested scriptblock would modify a copy)
        $readString = {
            param($bytes, $state)
            $j = $state.I
            while (-not ($bytes[$j] -eq 0 -and $bytes[$j + 1] -eq 0)) { $j += 2 }
            $v = [System.Text.Encoding]::Unicode.GetString($bytes, $state.I, $j - $state.I)
            $state.I = $j + 2
            $v
        }
        $r = @{}
        while ($st.I -lt $b.Length) {
            $st.I += 2                                              # '['
            $key = & $readString $b $st;  $st.I += 2                # ';'
            $name = & $readString $b $st; $st.I += 2
            $type = [BitConverter]::ToUInt32($b, $st.I); $st.I += 4 + 2
            $size = [BitConverter]::ToUInt32($b, $st.I); $st.I += 4 + 2
            $value = if ($type -eq 4) { [BitConverter]::ToUInt32($b, $st.I) }
                     else { [System.Text.Encoding]::Unicode.GetString($b, $st.I, $size).TrimEnd([char]0) }
            $st.I += $size + 2                                      # data + ']'
            $r["$key|$name"] = $value
        }
        $r
    }

    function Get-GpoPol {
        param([string]$GpoName)
        $b = Get-GpoBackupInfo -BackupPath $script:GpoDir | Where-Object Name -eq $GpoName | Sort-Object BackupTime -Descending | Select-Object -First 1
        $b | Should -Not -BeNullOrEmpty -Because "backup of $GpoName"
        Read-RegistryPol -Path (Join-Path $b.Folder 'DomainSysvol\GPO\Machine\registry.pol')
    }
}

AfterAll {
    Remove-Module GPO -Force -ErrorAction SilentlyContinue
    Remove-Item function:global:Write-Log -ErrorAction SilentlyContinue
}

Describe 'Get-GpoBackupInfo' {
    It 'lists every backup with name, id, folder and time' {
        $all = @(Get-GpoBackupInfo -BackupPath $script:GpoDir)
        $all.Count | Should -BeGreaterThan 40
        $one = $all | Where-Object Name -eq 'LLMNR-Disabled' | Select-Object -First 1
        $one.BackupId   | Should -Match '^[0-9A-Fa-f-]{36}$'
        $one.BackupTime | Should -Match '^\d{4}-\d{2}-\d{2}T'
        Test-Path $one.Folder | Should -BeTrue
    }
    It 'returns nothing for a missing folder' {
        @(Get-GpoBackupInfo -BackupPath (Join-Path $script:RepoRoot 'absent')).Count | Should -Be 0
    }
}

Describe 'Firewall-Hardened' {
    BeforeAll { $script:fw = Get-GpoPol 'Firewall-Hardened' }
    It 'enables the firewall and blocks inbound traffic by default on the three profiles' {
        foreach ($p in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
            $k = "SOFTWARE\Policies\Microsoft\WindowsFirewall\$p"
            $script:fw["$k|EnableFirewall"]       | Should -Be 1 -Because $p
            $script:fw["$k|DefaultInboundAction"] | Should -Be 1 -Because $p
            $script:fw["$k\Logging|LogDroppedPackets"] | Should -Be 1 -Because $p
        }
    }
    It 'does not disable the merge of local rules (role rules keep working)' {
        $script:fw.Keys | Where-Object { $_ -match 'AllowLocalPolicyMerge' } | Should -BeNullOrEmpty
    }
}

Describe 'WinRM-Server-Hardened' {
    BeforeAll { $script:srv = Get-GpoPol 'WinRM-Server-Hardened'; $script:k = 'Software\Policies\Microsoft\Windows\WinRM\Service' }
    It 'enforces channel binding (two values) and forbids RunAs credentials' {
        $script:srv["$($script:k)|CBTHardeningLevelStatus"] | Should -Be 1
        $script:srv["$($script:k)|CbtHardeningLevel"]       | Should -Be 'Strict'
        $script:srv["$($script:k)|DisableRunAs"]            | Should -Be 1
    }
    It 'disables Basic, CredSSP, unencrypted traffic and the HTTPS compatibility listener' {
        foreach ($n in 'AllowBasic', 'AllowCredSSP', 'AllowUnencryptedTraffic', 'HttpsCompatibilityListener') {
            $script:srv["$($script:k)|$n"] | Should -Be 0 -Because $n
        }
    }
    It 'defines the listener filters' {
        $script:srv["$($script:k)|AllowAutoConfig"] | Should -Be 1
        $script:srv.ContainsKey("$($script:k)|IPv4Filter") | Should -BeTrue
        $script:srv.ContainsKey("$($script:k)|IPv6Filter") | Should -BeTrue
    }
}

Describe 'WinRM-Client-Hardened' {
    BeforeAll { $script:cli = Get-GpoPol 'WinRM-Client-Hardened'; $script:k = 'Software\Policies\Microsoft\Windows\WinRM\Client' }
    It 'disables Basic, Digest, CredSSP and unencrypted traffic' {
        foreach ($n in 'AllowBasic', 'AllowDigest', 'AllowCredSSP', 'AllowUnencryptedTraffic') {
            $script:cli["$($script:k)|$n"] | Should -Be 0 -Because $n
        }
    }
    It 'never disallows Kerberos' {
        $script:cli["$($script:k)|AllowKerberos"] | Should -Be 1
    }
}

Describe 'PowerShellv2-Disabled' {
    BeforeAll {
        $b = Get-GpoBackupInfo -BackupPath $script:GpoDir | Where-Object Name -eq 'PowerShellv2-Disabled' | Select-Object -First 1
        $script:scripts = Join-Path $b.Folder 'DomainSysvol\GPO\Machine\Scripts'
    }
    It 'registers the startup script' {
        $ini = [System.IO.File]::ReadAllText((Join-Path $script:scripts 'PSscripts.ini'))
        $ini | Should -Match '\[Startup\]'
        $ini | Should -Match '0CmdLine=PowerShellv2-Disabled\.ps1'
    }
    It 'ships a startup script that parses and targets the PowerShell 2.0 feature only' {
        $file = Join-Path $script:scripts 'Startup\PowerShellv2-Disabled.ps1'
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$null, [ref]$errors) | Out-Null
        $errors | Should -BeNullOrEmpty
        $text = Get-Content $file -Raw
        $text | Should -Match 'MicrosoftWindowsPowerShellV2Root'
        $text | Should -Match 'PowerShell-V2'
        $text | Should -Not -Match 'SMB1'
    }
}

Describe 'Tier linking of the network baseline GPOs' {
    BeforeAll { $script:cfg = Get-Content (Join-Path $script:RepoRoot 'Config\GPO_config.json') -Raw | ConvertFrom-Json }
    It 'the old WinRM-Hardened name is gone' {
        $script:cfg.GPOs.Common.gpos | Should -Not -Contain 'WinRM-Hardened'
    }
    It 'only Servers sub-OUs get the WinRM service GPO; every computer OU gets the client GPO' {
        foreach ($tier in $script:cfg.TierMappings.PSObject.Properties) {
            foreach ($ou in $tier.Value.subOUs.PSObject.Properties) {
                $g = @($ou.Value.gpos)
                $label = "$($tier.Name)\$($ou.Name)"
                if ($ou.Name -eq 'Servers') { $g | Should -Contain 'WinRM-Server-Hardened' -Because $label }
                else                        { $g | Should -Not -Contain 'WinRM-Server-Hardened' -Because $label }
                if ($ou.Name -in 'Servers', 'PAW', 'Workstations') {
                    foreach ($n in 'WinRM-Client-Hardened', 'Firewall-Hardened', 'PowerShellv2-Disabled') { $g | Should -Contain $n -Because "$n on $label" }
                }
            }
        }
    }
}
