<#
.SYNOPSIS
    Read-only hardening report with per-control status and a compliance score.

.DESCRIPTION
    Used by `adhardened.ps1 -ReportOnly`. Never modifies Active Directory.
    Every control evaluates the CURRENT state of the domain, independently of what is enabled in
    Global_config.json (the column ConfiguredToApply tells whether a run would apply it).

    Statuses:
      Compliant      the control is in place
      NonCompliant   the control is missing or only partly applied
      NotApplicable  cannot be evaluated here (feature absent, GPO without backup in the repository,
                     functional level too low...) - excluded from the score
      Error          the check itself failed - excluded from the score

    Score = Compliant / (Compliant + NonCompliant), in percent, overall and per category.

    Functions exported:
      - Get-HardeningReport    : evaluate all controls (AD + PSO + GPO import/linking)
      - Get-HardeningScore     : compute counts and scores from a list of results (pure, offline)
      - ConvertTo-HardeningHtml: render a self-contained HTML page (pure, offline)
      - Export-HardeningReport : write HTML + CSV + JSON files, return their paths
      - Show-HardeningReport   : log a summary
#>

# Rollback-independent helpers --------------------------------------------------------------

function New-HardeningResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [ValidateSet('Compliant', 'NonCompliant', 'NotApplicable', 'Error')] [string]$Status,
        [string]$Details = '',
        [string]$Remediation = '',
        [bool]$ConfiguredToApply = $false
    )
    [PSCustomObject]@{
        Id                = $Id
        Category          = $Category
        Control           = $Control
        Status            = $Status
        ConfiguredToApply = $ConfiguredToApply
        Details           = $Details
        Remediation       = $Remediation
    }
}

function New-CheckOutcome {
    <# Helper for check scriptblocks: returns the hashtable understood by Invoke-HardeningCheck. #>
    param([bool]$Compliant, [string]$Details = '')
    @{ Status = $(if ($Compliant) { 'Compliant' } else { 'NonCompliant' }); Details = $Details }
}

function Invoke-HardeningCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [string]$Control,
        [Parameter(Mandatory)] [scriptblock]$Test,
        [string]$Remediation = '',
        [string]$FunctionKey,
        $EnabledFunctions
    )
    $configured = $false
    if ($FunctionKey -and $EnabledFunctions) { $configured = [bool]$EnabledFunctions.$FunctionKey }
    try {
        $outcome = & $Test
        New-HardeningResult -Id $Id -Category $Category -Control $Control -Status $outcome.Status `
            -Details $outcome.Details -Remediation $(if ($outcome.Status -eq 'NonCompliant') { $Remediation } else { '' }) `
            -ConfiguredToApply $configured
    } catch {
        New-HardeningResult -Id $Id -Category $Category -Control $Control -Status Error `
            -Details $_.Exception.Message -ConfiguredToApply $configured
    }
}

function Get-HardeningScore {
    <#
    .SYNOPSIS Counts and compliance scores from a list of results. Pure function (no AD access).
    .OUTPUTS  PSCustomObject: Score, Compliant, NonCompliant, NotApplicable, Error, Total, Categories[]
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results)

    function Get-Percent([int]$ok, [int]$ko) {
        if (($ok + $ko) -eq 0) { return $null }
        return [math]::Round(100.0 * $ok / ($ok + $ko), 1)
    }

    $count = {
        param($set, $status) @($set | Where-Object { $_.Status -eq $status }).Count
    }

    $categories = foreach ($group in ($Results | Group-Object Category | Sort-Object Name)) {
        $ok = & $count $group.Group 'Compliant'
        $ko = & $count $group.Group 'NonCompliant'
        [PSCustomObject]@{
            Category      = $group.Name
            Score         = Get-Percent $ok $ko
            Compliant     = $ok
            NonCompliant  = $ko
            NotApplicable = (& $count $group.Group 'NotApplicable')
            Error         = (& $count $group.Group 'Error')
        }
    }

    $okAll = & $count $Results 'Compliant'
    $koAll = & $count $Results 'NonCompliant'
    [PSCustomObject]@{
        Score         = Get-Percent $okAll $koAll
        Compliant     = $okAll
        NonCompliant  = $koAll
        NotApplicable = (& $count $Results 'NotApplicable')
        Error         = (& $count $Results 'Error')
        Total         = @($Results).Count
        Categories    = @($categories)
    }
}

# Evaluation --------------------------------------------------------------------------------

function Get-HardeningReport {
    <#
    .SYNOPSIS Evaluate the current hardening level of the domain (read-only).
    .PARAMETER Config           Parsed Global_config.json
    .PARAMETER GpoConfigPath    Path to GPO_config.json
    .PARAMETER PsoConfigPath    Path to PSO_config.json (optional)
    .PARAMETER GpoBackupPath    Folder with the GPO backups (to tell "not imported" from "no backup")
    .PARAMETER FunctionalLevels Hashtable from Test-FunctionalLevel
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Config,
        [Parameter(Mandatory)] [string]$GpoConfigPath,
        [Parameter()] [string]$PsoConfigPath,
        [Parameter()] [string]$GpoBackupPath,
        [Parameter()] [hashtable]$FunctionalLevels
    )

    $domain     = $Config.TargetDomain
    $rootDN     = $Config.RootDN
    $domainDN   = "DC=" + ($domain -replace '\.', ',DC=')
    $dsDn       = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$domainDN"
    $enabled    = $Config.Functions
    $results    = [System.Collections.Generic.List[object]]::new()
    $add        = { param($r) $results.Add($r) }

    Write-Log "`n=== Hardening report (read-only) ===" -Level INFO -Color Cyan

    # Read once, used by AD-01 and AD-02 (a failure surfaces as an Error result in each check)
    $ds = $null
    try { $ds = Get-ADObject -Identity $dsDn -Properties 'msDS-Other-Settings', dSHeuristics -ErrorAction Stop } catch { }

    # ---- Active Directory structure ---------------------------------------------------------
    foreach ($tier in $Config.TierNames) {
        & $add (Invoke-HardeningCheck -Id "STRUCT-$tier" -Category 'AD structure' -Control "Tier OU _$tier exists" `
            -FunctionKey 'InitializeADStructure' -EnabledFunctions $enabled `
            -Remediation "Enable 'InitializeADStructure'" -Test {
                $ou = Get-ADOrganizationalUnit -Identity "OU=_$tier,$rootDN" -ErrorAction SilentlyContinue
                New-CheckOutcome ([bool]$ou) "OU=_$tier,$rootDN"
            })
    }

    # ---- Domain-level hardening -------------------------------------------------------------
    & $add (Invoke-HardeningCheck -Id 'AD-01' -Category 'Domain hardening' -Control 'LDAP: unauthenticated bind denied (DenyUnauthenticatedBind=1)' `
        -FunctionKey 'SetADSIUnauthenticatedBind' -EnabledFunctions $enabled -Remediation "Enable 'SetADSIUnauthenticatedBind'" -Test {
            if (-not $ds) { throw 'Directory Service object unavailable' }
            $v = @($ds.'msDS-Other-Settings')
            New-CheckOutcome ($v -contains 'DenyUnauthenticatedBind=1') "msDS-Other-Settings: $($v -join '; ')"
        })

    & $add (Invoke-HardeningCheck -Id 'AD-02' -Category 'Domain hardening' -Control 'dSHeuristics: CVE-2021-42291 mitigation enforced' `
        -FunctionKey 'SetDsHeuristicsLDAPSecurity' -EnabledFunctions $enabled -Remediation "Enable 'SetDsHeuristicsLDAPSecurity'" -Test {
            if (-not $ds) { throw 'Directory Service object unavailable' }
            $h = [string]$ds.dSHeuristics
            $ok = ($h.Length -ge 29) -and ($h[27] -eq '1') -and ($h[28] -eq '1')
            New-CheckOutcome $ok "dSHeuristics = '$h' (characters 28 and 29 must be 1)"
        })

    & $add (Invoke-HardeningCheck -Id 'AD-03' -Category 'Domain hardening' -Control 'ms-DS-MachineAccountQuota = 0' `
        -FunctionKey 'SetmsDSMachineAccountQuota' -EnabledFunctions $enabled -Remediation "Enable 'SetmsDSMachineAccountQuota'" -Test {
            $q = (Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota')."ms-DS-MachineAccountQuota"
            New-CheckOutcome ($q -eq 0) "ms-DS-MachineAccountQuota = $q"
        })

    & $add (Invoke-HardeningCheck -Id 'AD-04' -Category 'Domain hardening' -Control 'Kerberos: krbtgt and DCs restricted to AES (0x18)' `
        -FunctionKey 'SetmsDSSupportedEncryptionTypes-krbtgt' -EnabledFunctions $enabled -Remediation "Enable 'SetmsDSSupportedEncryptionTypes-krbtgt'" -Test {
            $bad = @()
            $krb = Get-ADObject -Filter { Name -eq 'krbtgt' } -Properties 'msDS-SupportedEncryptionTypes' | Select-Object -First 1
            if ($krb -and $krb.'msDS-SupportedEncryptionTypes' -ne 0x18) { $bad += 'krbtgt' }
            foreach ($dc in @(Get-ADComputer -Filter { PrimaryGroupID -eq 516 } -Properties 'msDS-SupportedEncryptionTypes')) {
                if ($dc.'msDS-SupportedEncryptionTypes' -ne 0x18) { $bad += $dc.Name }
            }
            New-CheckOutcome ($bad.Count -eq 0) $(if ($bad.Count) { "Not AES-only: $($bad -join ', ')" } else { 'krbtgt and all DCs are AES-only' })
        })

    & $add (Invoke-HardeningCheck -Id 'AD-05' -Category 'Domain hardening' -Control 'AD Recycle Bin enabled' `
        -FunctionKey 'EnableRecycleBin' -EnabledFunctions $enabled -Remediation "Enable 'EnableRecycleBin' (irreversible)" -Test {
            $f = Get-ADOptionalFeature -Filter { Name -eq 'Recycle Bin Feature' }
            New-CheckOutcome ([bool]$f.EnabledScopes) 'Recycle Bin Feature'
        })

    & $add (Invoke-HardeningCheck -Id 'AD-06' -Category 'Domain hardening' -Control 'Windows LAPS schema extension present' `
        -FunctionKey 'EnableLAPS' -EnabledFunctions $enabled -Remediation "Enable 'EnableLAPS'" -Test {
            $schema = (Get-ADRootDSE).schemaNamingContext
            $attr = Get-ADObject -SearchBase $schema -Filter { Name -eq 'ms-LAPS-EncryptedPassword' } -ErrorAction SilentlyContinue
            New-CheckOutcome ([bool]$attr) 'attribute ms-LAPS-EncryptedPassword'
        })

    & $add (Invoke-HardeningCheck -Id 'AD-07' -Category 'Domain hardening' -Control "'Pre-Windows 2000 Compatible Access' is empty" `
        -FunctionKey 'LockPreWindows2000Group' -EnabledFunctions $enabled -Remediation "Enable 'LockPreWindows2000Group'" -Test {
            $m = @(Get-ADGroupMember -Identity 'S-1-5-32-554' -ErrorAction Stop)
            New-CheckOutcome ($m.Count -eq 0) "$($m.Count) member(s)$(if ($m.Count) { ': ' + (($m | ForEach-Object { $_.SamAccountName }) -join ', ') })"
        })

    & $add (Invoke-HardeningCheck -Id 'AD-08' -Category 'Tier 0 protection' -Control 'Tier 0 admin accounts are sensitive (cannot be delegated)' `
        -FunctionKey 'SetTier0AccountSensitive' -EnabledFunctions $enabled -Remediation "Enable 'SetTier0AccountSensitive'" -Test {
            $ou = "OU=Admins,OU=_Tier0,$rootDN"
            if (-not (Get-ADOrganizationalUnit -Identity $ou -ErrorAction SilentlyContinue)) {
                return @{ Status = 'NotApplicable'; Details = "OU not found: $ou" }
            }
            $users = @(Get-ADUser -SearchBase $ou -Filter * -Properties AccountNotDelegated)
            if ($users.Count -eq 0) { return @{ Status = 'NotApplicable'; Details = 'no account in the Tier 0 Admins OU' } }
            $bad = @($users | Where-Object { -not $_.AccountNotDelegated })
            New-CheckOutcome ($bad.Count -eq 0) "$($users.Count - $bad.Count)/$($users.Count) account(s) sensitive$(if ($bad.Count) { '; missing: ' + (($bad | ForEach-Object { $_.SamAccountName }) -join ', ') })"
        })

    & $add (Invoke-HardeningCheck -Id 'AD-09' -Category 'Tier 0 protection' -Control 'Authentication Policy Silo configured' `
        -FunctionKey 'NewTier0AuthenticationPolicySilo' -EnabledFunctions $enabled -Remediation "Enable 'NewTier0AuthenticationPolicySilo'" -Test {
            $silo = @(Get-ADAuthenticationPolicySilo -Filter * -ErrorAction Stop)
            if ($silo.Count -eq 0) { return @{ Status = 'NonCompliant'; Details = 'no silo defined' } }
            $enforced = @($silo | Where-Object { $_.Enforce })
            New-CheckOutcome ($enforced.Count -gt 0) "$($silo.Count) silo(s), $($enforced.Count) in Enforce mode (others are Audit)"
        })

    foreach ($tier in $Config.TierNames) {
        $self = "${tier}_Admins"
        & $add (Invoke-HardeningCheck -Id "DELEG-$tier" -Category 'Tier 0 protection' -Control "Tier OU _$tier delegated to $self" `
            -FunctionKey 'SetTierOUDelegation' -EnabledFunctions $enabled -Remediation "Enable 'SetTierOUDelegation'" -Test {
                $ouDn = "OU=_$tier,$rootDN"
                if (-not (Get-ADOrganizationalUnit -Identity $ouDn -ErrorAction SilentlyContinue)) {
                    return @{ Status = 'NotApplicable'; Details = "OU not found: $ouDn" }
                }
                $acl = Get-Acl -Path "AD:$ouDn"
                $ace = @($acl.Access | Where-Object {
                    $_.AccessControlType -eq 'Allow' -and "$($_.IdentityReference)" -like "*\$self" -and
                    ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
                })
                New-CheckOutcome ($ace.Count -gt 0) "FullControl ACE for $self : $(if ($ace.Count) { 'present' } else { 'absent' })"
            })
    }

    # ---- Fine-grained password policies -----------------------------------------------------
    if ($PsoConfigPath -and (Test-Path $PsoConfigPath)) {
        $psoCfg = Get-Content -Path $PsoConfigPath -Raw | ConvertFrom-Json
        foreach ($p in @($psoCfg.PSOs)) {
            $pso = $p
            & $add (Invoke-HardeningCheck -Id "PSO-$($pso.Name -replace '^PSO-', '')" -Category 'Password policy (PSO)' -Control "PSO $($pso.Name) in place and applied" `
                -FunctionKey 'SetFineGrainedPasswordPolicies' -EnabledFunctions $enabled -Remediation "Enable 'SetFineGrainedPasswordPolicies'" -Test {
                    $e = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$($pso.Name)'" -ErrorAction Stop
                    if (-not $e) { return @{ Status = 'NonCompliant'; Details = 'PSO does not exist' } }
                    $problems = @()
                    if ($e.MinPasswordLength -lt [int]$pso.MinPasswordLength) { $problems += "MinPasswordLength $($e.MinPasswordLength) < $($pso.MinPasswordLength)" }
                    if (-not $e.ComplexityEnabled -and [bool]$pso.ComplexityEnabled) { $problems += 'complexity disabled' }
                    if ($e.ReversibleEncryptionEnabled) { $problems += 'reversible encryption enabled' }
                    if ([int]$pso.LockoutThreshold -gt 0 -and ($e.LockoutThreshold -eq 0 -or $e.LockoutThreshold -gt [int]$pso.LockoutThreshold)) {
                        $problems += "LockoutThreshold $($e.LockoutThreshold) (expected <= $($pso.LockoutThreshold))"
                    }
                    $subjects = @(Get-ADFineGrainedPasswordPolicySubject -Identity $pso.Name -ErrorAction SilentlyContinue)
                    if ($subjects.Count -eq 0) { $problems += 'applied to no group/user' }
                    New-CheckOutcome ($problems.Count -eq 0) $(if ($problems.Count) { $problems -join '; ' } else { "$($subjects.Count) subject(s), length >= $($e.MinPasswordLength)" })
                })
        }
    } else {
        & $add (New-HardeningResult -Id 'PSO-CONFIG' -Category 'Password policy (PSO)' -Control 'PSO configuration' -Status NotApplicable `
            -Details 'PSO_config.json not found')
    }

    # ---- GPO import and linking -------------------------------------------------------------
    if (Test-Path $GpoConfigPath) {
        $gpoConfig  = Get-Content -Path $GpoConfigPath -Raw | ConvertFrom-Json
        $expected   = @(Get-GPOsToImport -FunctionalLevels $(if ($FunctionalLevels) { $FunctionalLevels } else { @{ ForestLevel = 2019 } }) -GPOConfig $gpoConfig)
        $backupSet  = if ($GpoBackupPath) { @(Get-GpoBackupInfo -BackupPath $GpoBackupPath | ForEach-Object Name | Select-Object -Unique) } else { @() }

        # One query for every GPO of the domain instead of one per GPO
        $domainGpos = $null
        try {
            $domainGpos = @{}
            foreach ($g in Get-GPO -All -Domain $domain -ErrorAction Stop) { $domainGpos[$g.DisplayName] = $true }
        } catch {
            $domainGpos = $null
            & $add (New-HardeningResult -Id 'GPO-LIST' -Category 'GPO' -Control 'List the GPOs of the domain' -Status Error -Details $_.Exception.Message)
        }

        # name -> list of OU DNs where it must be linked
        $expectedLinks = @{}
        foreach ($tier in $Config.TierNames) {
            $mapping = $gpoConfig.TierMappings.$tier
            if (-not $mapping) { continue }
            foreach ($t in @(Resolve-TierSubOUMapping -TierMapping $mapping -TierName $tier -RootDN $rootDN)) {
                foreach ($g in $t.GPOs) {
                    if (-not $expectedLinks.ContainsKey($g)) { $expectedLinks[$g] = [System.Collections.Generic.List[string]]::new() }
                    $expectedLinks[$g].Add($t.OU)
                }
            }
        }

        $linkCache = @{}
        foreach ($gpoName in ($(if ($domainGpos) { $expected | Select-Object -Unique | Sort-Object } else { @() }))) {
            $name = $gpoName
            & $add (Invoke-HardeningCheck -Id "GPO-$name" -Category 'GPO' -Control "GPO $name imported and linked" `
                -FunctionKey 'ImportSecurityHardeningGPOs' -EnabledFunctions $enabled `
                -Remediation "Run ImportSecurityHardeningGPOs then ApplyGPOsToTiers" -Test {
                    if (-not $domainGpos.ContainsKey($name)) {
                        if ($backupSet -and ($name -notin $backupSet)) {
                            return @{ Status = 'NotApplicable'; Details = 'not in the domain and no backup in the GPO folder (export it into the GPO folder first)' }
                        }
                        return @{ Status = 'NonCompliant'; Details = 'not imported in the domain' }
                    }
                    $targets = @($expectedLinks[$name])
                    if ($targets.Count -eq 0) { return @{ Status = 'NonCompliant'; Details = 'imported but not mapped to any OU in TierMappings' } }
                    $missing = @(); $checked = 0
                    foreach ($ou in $targets) {
                        if (-not $linkCache.ContainsKey($ou)) {
                            $linkCache[$ou] = $null
                            if (Get-ADOrganizationalUnit -Identity $ou -ErrorAction SilentlyContinue) {
                                $linkCache[$ou] = @((Get-GPInheritance -Target $ou -Domain $domain -ErrorAction SilentlyContinue).GpoLinks)
                            }
                        }
                        if ($null -eq $linkCache[$ou]) { continue }   # OU absent: nothing to link to
                        $checked++
                        $link = @($linkCache[$ou] | Where-Object { $_.DisplayName -eq $name })
                        if ($link.Count -eq 0 -or -not $link[0].Enabled) { $missing += $ou }
                    }
                    if ($checked -eq 0) { return @{ Status = 'NotApplicable'; Details = 'none of the target OUs exist' } }
                    New-CheckOutcome ($missing.Count -eq 0) $(if ($missing.Count) { "not linked (or disabled) on: $($missing -join ' | ')" } else { "linked on $checked OU(s)" })
                })
        }
    } else {
        & $add (New-HardeningResult -Id 'GPO-CONFIG' -Category 'GPO' -Control 'GPO configuration' -Status NotApplicable `
            -Details "GPO_config.json not found: $GpoConfigPath")
    }

    return @($results)
}

# Output ------------------------------------------------------------------------------------

function ConvertTo-HardeningHtml {
    <#
    .SYNOPSIS Render the results as ONE self-contained HTML page (inline CSS/JS, no external resource).
    .DESCRIPTION
        Score gauge, per-category bars, status counters and a filterable / searchable table.
        Light and dark themes follow the system setting. Every value is HTML-encoded.
        Pure function: no AD access, returns the HTML text.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results,
        [string]$TargetDomain = '',
        [string]$GeneratedAt = (Get-Date -Format 'yyyy-MM-dd HH:mm')
    )

    $enc   = { param($v) [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $score = Get-HardeningScore -Results $Results
    $pctText = if ($null -eq $score.Score) { 'n/a' } else { "$($score.Score)" }
    $pctNum  = if ($null -eq $score.Score) { 0 } else { [double]$score.Score }
    $level   = if ($null -eq $score.Score) { 'na' } elseif ($pctNum -ge 80) { 'good' } elseif ($pctNum -ge 50) { 'warn' } else { 'bad' }
    $inv     = [System.Globalization.CultureInfo]::InvariantCulture

    $label = @{ Compliant = 'Compliant'; NonCompliant = 'Non-compliant'; NotApplicable = 'Not applicable'; Error = 'Error' }
    $css   = @{ Compliant = 'ok'; NonCompliant = 'ko'; NotApplicable = 'na'; Error = 'err' }

    $bars = New-Object System.Text.StringBuilder
    foreach ($c in $score.Categories) {
        $v   = if ($null -eq $c.Score) { 0 } else { [double]$c.Score }
        $txt = if ($null -eq $c.Score) { 'n/a' } else { "$($c.Score) %" }
        $lv  = if ($null -eq $c.Score) { 'na' } elseif ($v -ge 80) { 'good' } elseif ($v -ge 50) { 'warn' } else { 'bad' }
        [void]$bars.AppendLine("<div class=""bar""><span class=""bar-name"">$(& $enc $c.Category)</span><span class=""track""><span class=""fill $lv"" style=""width:$($v.ToString('0.#', $inv))%""></span></span><span class=""bar-val"">$txt</span><span class=""bar-sub"">$($c.Compliant) ok / $($c.NonCompliant) ko</span></div>")
    }

    $rows = New-Object System.Text.StringBuilder
    $order = @{ NonCompliant = 0; Error = 1; Compliant = 2; NotApplicable = 3 }
    foreach ($r in ($Results | Sort-Object { $order[[string]$_.Status] }, Category, Id)) {
        $st = [string]$r.Status
        $cfg = if ($r.ConfiguredToApply) { 'yes' } else { 'no' }
        $detail = & $enc $r.Details
        if ($r.Remediation) { $detail += "<div class=""fix"">Fix: $(& $enc $r.Remediation)</div>" }
        [void]$rows.AppendLine("<tr data-status=""$st""><td><span class=""badge $($css[$st])"">$($label[$st])</span></td><td>$(& $enc $r.Category)</td><td><code>$(& $enc $r.Id)</code></td><td>$(& $enc $r.Control)</td><td>$cfg</td><td>$detail</td></tr>")
    }

    $template = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ADHardened - Hardening report</title>
<style>
:root{color-scheme:light;--bg:#f6f7f9;--card:#fff;--text:#1c2430;--muted:#5d6b7c;--line:#dfe3e8;--good:#1a7f45;--warn:#a86400;--bad:#c0392b;--na:#6b7686;--goodbg:#e3f4ea;--warnbg:#fdf0d9;--badbg:#fbe5e2;--nabg:#eceff3}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#12161c;--card:#1b212a;--text:#e6eaf0;--muted:#9aa6b5;--line:#2c3541;--good:#4cc27f;--warn:#e0a53a;--bad:#ef6b5c;--na:#8f9bab;--goodbg:#1d3a2a;--warnbg:#3b2f17;--badbg:#412220;--nabg:#262d37}}
:root[data-theme=dark]{color-scheme:dark;--bg:#12161c;--card:#1b212a;--text:#e6eaf0;--muted:#9aa6b5;--line:#2c3541;--good:#4cc27f;--warn:#e0a53a;--bad:#ef6b5c;--na:#8f9bab;--goodbg:#1d3a2a;--warnbg:#3b2f17;--badbg:#412220;--nabg:#262d37}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 2px}
.sub{color:var(--muted);margin:0 0 20px}
.top{display:grid;grid-template-columns:minmax(220px,260px) 1fr;gap:16px;margin-bottom:16px}
@media (max-width:720px){.top{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.gauge{text-align:center}
.big{font-size:54px;font-weight:700;line-height:1}
.big small{font-size:22px;font-weight:600}
.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.na{color:var(--na)}
.gauge .lbl{color:var(--muted);margin-top:6px}
.counts{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin-top:14px}
.count{border-radius:8px;padding:4px 10px;font-weight:600;font-size:12px}
.count.ok{background:var(--goodbg);color:var(--good)}.count.ko{background:var(--badbg);color:var(--bad)}.count.na{background:var(--nabg);color:var(--na)}.count.err{background:var(--warnbg);color:var(--warn)}
.bar{display:grid;grid-template-columns:minmax(120px,190px) 1fr 56px 90px;gap:10px;align-items:center;margin:8px 0}
@media (max-width:560px){.bar{grid-template-columns:1fr 56px}.track,.bar-sub{display:none}}
.track{height:10px;background:var(--nabg);border-radius:6px;overflow:hidden;display:block}
.fill{display:block;height:100%;border-radius:6px;background:currentColor}
.bar-val{font-weight:700;text-align:right}.bar-sub{color:var(--muted);font-size:12px}
.tools{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px}
.tools button{border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:999px;padding:5px 12px;cursor:pointer;font:inherit}
.tools button[aria-pressed=true]{background:var(--text);color:var(--bg);border-color:var(--text)}
.tools input{flex:1;min-width:180px;border:1px solid var(--line);background:var(--card);color:var(--text);border-radius:8px;padding:6px 10px;font:inherit}
.tablewrap{overflow-x:auto;padding:0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);white-space:nowrap}
tr:last-child td{border-bottom:0}
code{font-size:12px}
.badge{display:inline-block;border-radius:6px;padding:2px 8px;font-size:12px;font-weight:600;white-space:nowrap}
.badge.ok{background:var(--goodbg);color:var(--good)}.badge.ko{background:var(--badbg);color:var(--bad)}.badge.na{background:var(--nabg);color:var(--na)}.badge.err{background:var(--warnbg);color:var(--warn)}
.fix{color:var(--muted);margin-top:3px;font-size:12px}
.empty{padding:16px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:16px}
</style>
</head>
<body>
<main>
<h1>ADHardened - Hardening report</h1>
<p class="sub">Domain: __DOMAIN__ &middot; Generated: __DATE__ &middot; Read-only evaluation</p>
<section class="top">
  <div class="card gauge">
    <div class="big __LEVEL__">__SCORE__<small>%</small></div>
    <div class="lbl">Compliance score</div>
    <div class="counts">
      <span class="count ok">__OK__ compliant</span>
      <span class="count ko">__KO__ non-compliant</span>
      <span class="count na">__NA__ n/a</span>
      <span class="count err">__ERR__ errors</span>
    </div>
  </div>
  <div class="card">
    <strong>By category</strong>
__BARS__
  </div>
</section>
<div class="tools" role="group" aria-label="Filter by status">
  <button type="button" data-f="all" aria-pressed="true">All (__TOTAL__)</button>
  <button type="button" data-f="NonCompliant" aria-pressed="false">Non-compliant</button>
  <button type="button" data-f="Error" aria-pressed="false">Errors</button>
  <button type="button" data-f="Compliant" aria-pressed="false">Compliant</button>
  <button type="button" data-f="NotApplicable" aria-pressed="false">Not applicable</button>
  <input id="q" type="search" placeholder="Search id, control, details..." aria-label="Search controls">
</div>
<div class="card tablewrap">
<table id="t">
<thead><tr><th>Status</th><th>Category</th><th>Id</th><th>Control</th><th>Applied by config</th><th>Details</th></tr></thead>
<tbody>
__ROWS__
</tbody>
</table>
<div class="empty" id="none" hidden>No control matches the filter.</div>
</div>
<footer>Score = compliant / (compliant + non-compliant). Not applicable and error results are excluded. Generated by adhardened.ps1 -ReportOnly.</footer>
</main>
<script>
(function(){
  var f='all', q='';
  var rows=[].slice.call(document.querySelectorAll('#t tbody tr'));
  var btns=[].slice.call(document.querySelectorAll('.tools button'));
  function apply(){
    var shown=0;
    rows.forEach(function(r){
      var ok=(f==='all'||r.getAttribute('data-status')===f)&&(!q||r.textContent.toLowerCase().indexOf(q)>-1);
      r.hidden=!ok; if(ok) shown++;
    });
    document.getElementById('none').hidden=shown>0;
  }
  btns.forEach(function(b){b.addEventListener('click',function(){
    f=b.getAttribute('data-f');
    btns.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false');});
    apply();
  });});
  document.getElementById('q').addEventListener('input',function(e){q=e.target.value.toLowerCase().trim();apply();});
})();
</script>
</body>
</html>
'@

    return $template.
        Replace('__DOMAIN__', (& $enc $TargetDomain)).
        Replace('__DATE__',   (& $enc $GeneratedAt)).
        Replace('__LEVEL__',  $level).
        Replace('__SCORE__',  $pctText).
        Replace('__OK__',     "$($score.Compliant)").
        Replace('__KO__',     "$($score.NonCompliant)").
        Replace('__NA__',     "$($score.NotApplicable)").
        Replace('__ERR__',    "$($score.Error)").
        Replace('__TOTAL__',  "$($score.Total)").
        Replace('__BARS__',   $bars.ToString()).
        Replace('__ROWS__',   $rows.ToString())
}

function Export-HardeningReport {
    <#
    .SYNOPSIS Write the report as HTML (human readable), CSV (one line per control) and JSON (results + score).
    .OUTPUTS  PSCustomObject with Html, Csv and Json paths.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results,
        [Parameter(Mandatory)] [string]$OutputDirectory,
        [string]$TargetDomain
    )
    if (-not (Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csv   = Join-Path $OutputDirectory "hardening_report_${stamp}.csv"
    $json  = Join-Path $OutputDirectory "hardening_report_${stamp}.json"
    $html  = Join-Path $OutputDirectory "hardening_report_${stamp}.html"
    $score = Get-HardeningScore -Results $Results

    $Results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false
    [ordered]@{
        GeneratedAt  = (Get-Date -Format 'o')
        TargetDomain = $TargetDomain
        Score        = $score
        Results      = @($Results)
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $json -Encoding UTF8 -WhatIf:$false -Confirm:$false

    ConvertTo-HardeningHtml -Results $Results -TargetDomain $TargetDomain |
        Set-Content -Path $html -Encoding UTF8 -WhatIf:$false -Confirm:$false

    [PSCustomObject]@{ Html = $html; Csv = $csv; Json = $json }
}

function Show-HardeningReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Results)

    $score = Get-HardeningScore -Results $Results
    Write-Log "`n=== Hardening score ===" -Level INFO -Color Cyan
    $overall = if ($null -eq $score.Score) { 'n/a' } else { "$($score.Score) %" }
    Write-Log "Overall: $overall   (compliant $($score.Compliant), non-compliant $($score.NonCompliant), not applicable $($score.NotApplicable), errors $($score.Error))" -Level INFO
    foreach ($c in $score.Categories) {
        $pct = if ($null -eq $c.Score) { 'n/a' } else { "$($c.Score) %" }
        Write-Log ("  {0,-28} {1,8}   ({2} ok / {3} ko)" -f $c.Category, $pct, $c.Compliant, $c.NonCompliant) -Level INFO
    }

    $ko = @($Results | Where-Object { $_.Status -eq 'NonCompliant' })
    if ($ko.Count -gt 0) {
        Write-Log "`nNon-compliant controls:" -Level WARN
        foreach ($r in $ko) { Write-Log ("  [KO] {0,-14} {1}  -  {2}" -f $r.Id, $r.Control, $r.Details) -Level WARN }
    }
    $err = @($Results | Where-Object { $_.Status -eq 'Error' })
    foreach ($r in $err) { Write-Log ("  [ERR] {0,-13} {1}  -  {2}" -f $r.Id, $r.Control, $r.Details) -Level ERROR }
}

Export-ModuleMember -Function `
    Get-HardeningReport, Get-HardeningScore, Export-HardeningReport, Show-HardeningReport, ConvertTo-HardeningHtml
