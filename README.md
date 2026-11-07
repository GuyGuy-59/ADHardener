# ADHardened

Automated Active Directory hardening with tiered administration, security baseline GPOs, defense-in-depth controls, and best-effort rollback.

**ADHardened** helps security teams deploy and maintain a hardened Active Directory security architecture based on a tiered administration model.

It automates the creation of Tier 0, Tier 1, and Tier 2 administrative structures, applies security-focused Group Policy Objects, enables optional advanced Active Directory hardening, and provides state backups for controlled rollback.

> **ADHardened is designed as a security automation and reference framework. Always test changes in a lab environment before deploying them to production.**

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Architecture](#architecture)
* [Prerequisites](#prerequisites)
* [Usage](#usage)
* [Configuration](#configuration)
* [Module Structure](#module-structure)
* [GPO Linking Strategy](#gpo-linking-strategy)
* [Advanced AD Hardening](#advanced-ad-hardening)
* [Rollback](#rollback)
* [Security Considerations](#security-considerations)
* [Testing](#testing)
* [Roadmap](#roadmap)

---

<a id="overview"></a>

## 📦 Overview

Active Directory is one of the most critical components of a Windows enterprise environment.

A compromise of privileged identities, Domain Controllers, or administrative workstations can provide an attacker with control over the entire domain.

**ADHardened** helps reduce this attack surface by automating a tiered security model:

```text
                    ┌─────────────────────┐
                    │       TIER 0        │
                    │                     │
                    │ Domain Controllers  │
                    │ Enterprise Admins   │
                    │ Domain Admins       │
                    │ Critical Identity   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │       TIER 1        │
                    │                     │
                    │ Servers             │
                    │ Server Admins       │
                    │ Infrastructure      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │       TIER 2        │
                    │                     │
                    │ Workstations        │
                    │ End Users           │
                    │ Helpdesk             │
                    └─────────────────────┘
```

ADHardened is designed to be:

* **Idempotent** — safe to run repeatedly.
* **Auditable** — every execution generates logs and state snapshots.
* **Reversible** — changes are backed up before modification whenever possible.
* **Modular** — individual security functions can be enabled or disabled.
* **Dry-run friendly** — changes can be previewed using `-DryRun` and `-WhatIf`.

---

<a id="features"></a>

## ✨ Features

### Active Directory Architecture

* Tier 0 / Tier 1 / Tier 2 OU structure
* Tier 1 Legacy support
* Dedicated administrative containers
* Tier-specific security boundaries
* Automated group creation

### Group Policy Security

* Security-hardening GPO import
* Forest functional level-aware selection
* Granular GPO linking
* Separate policies for:

  * Domain Controllers
  * Servers
  * Workstations
  * Users
  * Administrators
* Network baseline GPOs:

  * `Firewall-Hardened`: firewall enabled on all profiles, inbound blocked by default
  * `WinRM-Server-Hardened` / `WinRM-Client-Hardened`: no Basic / Digest / CredSSP / unencrypted traffic, channel binding Strict, listener filter
  * `PowerShellv2-Disabled`: PowerShell 2.0 engine removed (same idea as `SMBv1-Disabled`)

### Active Directory Hardening

* ADSI unauthenticated bind hardening
* DsHeuristics LDAP security mitigation (CVE-2021-42291 / KB5008383)
* Machine Account Quota configuration
* Kerberos encryption type hardening
* Active Directory Recycle Bin enablement
* LAPS prerequisites
* BitLocker prerequisites
* Pre-Windows 2000 group lockdown
* Tier 0 account delegation protection
* Privileged group auditing
* Authentication Policy Silos
* Tier OU ACL delegation
* Fine-Grained Password Policies (PSO) per population: tier admins, service accounts, standard users

### Reporting

* `-ReportOnly` mode: read-only evaluation of every control
* Self-contained HTML report, plus CSV and JSON, with a compliance score (overall and per category)

### Operational Safety

* Preflight environment validation
* Centralized logging
* Severity-based log levels
* JSON state baseline capture
* Best-effort rollback driven by one rollback journal per run
* `-WhatIf` support
* `-DryRun` mode
* Offline Pester test suite

---

<a id="architecture"></a>

## 🏗️ Architecture

ADHardened separates administrative responsibilities into security tiers.

### Tier 0

Assets and identities that control the Active Directory environment.

Examples:

* Domain Controllers
* Domain Admins
* Enterprise Admins
* Schema Admins
* Tier 0 administrative accounts

### Tier 1

Server and infrastructure administration.

Examples:

* Member servers
* Application servers
* Infrastructure services
* Server administrators

### Tier 2

User and workstation administration.

Examples:

* Workstations
* Standard users
* Helpdesk operations

The goal is to prevent administrative credentials from being reused across security boundaries.

---

<a id="prerequisites"></a>

## ✅ Prerequisites

* Windows Server with RSAT
* Active Directory Domain Services
* PowerShell 5.1 or later
* PowerShell 7 supported with Windows Compatibility where required
* `ActiveDirectory` PowerShell module
* `GroupPolicy` PowerShell module
* `LAPS` module (optional)
* Domain Administrator privileges
* Active Directory forest/domain functional level ≥ Windows Server 2008 R2

> The Active Directory Recycle Bin requires a forest functional level of at least Windows Server 2008 R2.

---

<a id="usage"></a>

## ▶️ Usage

The main deployment script is:

```text
adhardened.ps1
```

The rollback script is:

```text
restore.ps1
```

### Standard execution

```powershell
.\adhardened.ps1
```

---

### Recommended: Dry Run

Before applying changes:

```powershell
.\adhardened.ps1 -DryRun
```

Dry-run mode:

* Validates the environment.
* Checks required modules.
* Checks permissions and connectivity.
* Captures the current state baseline.
* Displays which actions would be performed.
* Does not modify Active Directory.

---

### Report only (hardening score)

```powershell
.\adhardened.ps1 -ReportOnly
```

Read-only. Nothing is modified and no rollback journal is created. The script evaluates the
**current** state of the domain for every control (domain hardening, Tier 0 protection, PSO,
GPO import and linking) and writes:

```text
reports/hardening_report_YYYYMMDD_HHMMSS.html   readable report (open in a browser)
reports/hardening_report_YYYYMMDD_HHMMSS.csv    one line per control
reports/hardening_report_YYYYMMDD_HHMMSS.json   results + score
```

The HTML file is self-contained (no external resource, safe to mail or archive): score gauge,
score per category, status counters, and a table filterable by status and searchable by text.
Light/dark theme follows the system setting.

Each line has a `Status`:

| Status | Meaning |
| --- | --- |
| `Compliant` | The control is in place |
| `NonCompliant` | Missing or only partly applied (`Remediation` says which function to enable) |
| `NotApplicable` | Cannot be evaluated (OU missing, GPO without backup in the repository...) - not scored |
| `Error` | The check itself failed - not scored |

`Score = Compliant / (Compliant + NonCompliant)`, reported overall and per category. The column
`ConfiguredToApply` shows whether the control is enabled in `Global_config.json`, so you can tell
"not yet applied" from "not intended".

---

### WhatIf mode

```powershell
.\adhardened.ps1 -WhatIf
```

All Active Directory modification functions support `-WhatIf` where applicable.

---

### Debug logging

```powershell
.\adhardened.ps1 -LogLevel DEBUG
```

---

### Skip preflight checks

Not recommended:

```powershell
.\adhardened.ps1 -SkipPreflight
```

---

### Skip the rollback journal

Not recommended (the run cannot be restored afterwards):

```powershell
.\adhardened.ps1 -SkipBackup
```

### Also capture the legacy state baseline

```powershell
.\adhardened.ps1 -LegacyStateBackup
```

---

---

## Logs and Backups

### Logs

```text
logs/adhardened_YYYYMMDD_HHMMSS.log
```

### Rollback journal (one file per run)

```text
backups/journal/rollback_YYYYMMDD_HHMMSS.json
backups/journal/gpo_preimport_*/          previous content of GPOs overwritten by the run
```

### Reports

```text
reports/hardening_report_YYYYMMDD_HHMMSS.html
reports/hardening_report_YYYYMMDD_HHMMSS.csv
reports/hardening_report_YYYYMMDD_HHMMSS.json
```

### Legacy backups (only with `-LegacyStateBackup` or older versions)

```text
backups/state_backup_YYYYMMDD_HHMMSS.json
backups/acl/acl_*.json
backups/preWin2000_members_*.json
```

---

<a id="configuration"></a>

## ⚙️ Configuration

ADHardened uses JSON configuration files located in the `Config/` directory.

### Global_config.json

This file controls the overall deployment.

Example:

```json
{
    "RootDN": "DC=lab,DC=local",
    "AdmName": "ADM",
    "TierNames": [
        "Tier0",
        "Tier1",
        "Tier2",
        "Tier1_Legacy"
    ],
    "TargetDomain": "lab.local",
    "GPOBackupPath": "GPO",
    "Functions": {
        "InitializeADStructure": true,
        "ImportSecurityHardeningGPOs": true,
        "ApplyGPOsToTiers": true,
        "SetADSIUnauthenticatedBind": true,
        "SetDsHeuristicsLDAPSecurity": true,
        "SetTierOUDelegation": false,
        "SetFineGrainedPasswordPolicies": false,
        "NewTier0AuthenticationPolicySilo": false,
        "LockPreWindows2000Group": false,
        "GetPrivilegedGroupAudit": false,
        "SetTier0AccountSensitive": false
    }
}
```

Security-sensitive functions are disabled by default and must be explicitly enabled.

---

### GPO_config.json

Defines which GPOs are linked to which tiers and organizational units.

See [GPO Linking Strategy](#gpo-linking-strategy).

---

### PSO_config.json

Fine-Grained Password Policies, applied by `SetFineGrainedPasswordPolicies` (domain functional level 2008 or later).
One PSO per population, each targeting global security groups:

| PSO | Precedence | Min length | Lockout | Groups |
| --- | --- | --- | --- | --- |
| `PSO-Tier0-Admins` | 10 | 16 | 3 failures / 15 min | `Tier0_Admins` |
| `PSO-Tier1-Admins` | 20 | 15 | 3 failures / 15 min | `Tier1_Admins`, `Tier1_Legacy_Admins` |
| `PSO-Tier2-Admins` | 30 | 15 | 3 failures / 15 min | `Tier2_Admins` |
| `PSO-Service-Accounts` | 40 | 25 | none (a lockout would be a denial of service) | `Service-Accounts` |
| `PSO-Standard-Users` | 100 | 12 | 3 failures / 15 min | `Tier2_Users` |

Behavior:

* Idempotent: a PSO that already matches is left untouched; subjects already applied are skipped.
* A missing group is skipped with a warning (the group `Service-Accounts` is not created by ADHardened).
* Every change goes into the rollback journal (PSO created, previous settings, subject added).
* The Default Domain Policy is **not** modified. PSOs only affect members of the listed groups.
* Check the result with `Get-ADUserResultantPasswordPolicy -Identity <user>`.

Test the lockout settings on administrator accounts in a lab first.

---

### Silo_config.json

Authentication Policy Silo configuration:

```json
{
    "PolicyName": "Tier0-AuthPolicy",
    "SiloName": "Tier0-Silo",
    "Mode": "Audit",
    "TGTLifetimeMinutes": 45,
    "Members": {
        "Users": [
            "t0-admin1",
            "t0-admin2"
        ],
        "Computers": [
            "DC01$",
            "DC02$",
            "PAW-T0-01$"
        ],
        "Services": []
    }
}
```

Start with:

```json
"Mode": "Audit"
```

Only switch to:

```json
"Mode": "Enforce"
```

after validating the resulting audit events and authentication behavior.

---

<a id="module-structure"></a>

## 🧩 Module Structure

### Logging.psm1

Centralized logging.

Responsibilities:

* Console output
* File logging
* Severity levels
* Timestamped execution logs

---

### Journal.psm1

Single per-run rollback journal.

Responsibilities:

* One `rollback_<timestamp>.json` per run, flushed after every change
* Entries for attributes, created objects, ACLs, group members, GPO imports and links, PSO, silo assignments
* Replay in reverse order (`Restore-RunJournal`)
* No-op when no journal is active, so hardening functions still work standalone

---

### Reporting.psm1

Read-only hardening report.

Responsibilities:

* Evaluate AD hardening, Tier 0 protection, PSO and GPO import / linking
* Compliance score overall and per category
* HTML (self-contained), CSV and JSON export

---

### Validation.psm1

Preflight validation.

Checks:

* Required PowerShell modules
* PowerShell version
* Administrative privileges
* Active Directory connectivity
* Configuration integrity

---

### StateManagement.psm1

Legacy state baseline (superseded by `Journal.psm1`, kept for older backups and `-LegacyStateBackup`).

Responsibilities:

* AD baseline capture
* OU state
* Group state
* GPO links
* Domain attributes
* Account delegation flags
* Authentication Policy Silos
* Privileged group membership
* Best-effort restoration

---

### GPO.psm1

GPO management.

Responsibilities:

* GPO import
* GPO detection
* Granular linking
* Idempotent GPO deployment

---

### ADStructure.psm1

Active Directory structure creation.

Responsibilities:

* Tier OU creation
* Administrative OU creation
* Group creation
* Tier hierarchy deployment

---

### ADHardening.psm1

Security hardening functions.

Responsibilities:

* Domain-level hardening
* Kerberos security settings
* Machine Account Quota
* ADSI binding security
* DsHeuristics LDAP security mitigation (CVE-2021-42291)
* Active Directory Recycle Bin
* LAPS
* BitLocker prerequisites
* OU ACL delegation
* Authentication Policy Silos
* Privileged group auditing
* Pre-Windows 2000 group lockdown
* Tier 0 account protection

---

<a id="gpo-linking-strategy"></a>

## 🔗 GPO Linking Strategy

GPOs are linked to the most appropriate organizational unit rather than automatically linking everything at the tier root.

This avoids applying inappropriate user or computer policies.

### Granular configuration

Example:

```json
{
    "TierMappings": {
        "Tier2": {
            "description": "Workstations and end users",
            "subOUs": {
                "Workstations": {
                    "gpos": [
                        "Bitlocker-Enabled"
                    ]
                },
                "Users": {
                    "gpos": [
                        "ScreenLock-enabled"
                    ]
                },
                "Admins": {
                    "gpos": []
                }
            }
        }
    }
}
```

The special `_root` key can be used to link a GPO directly to the tier root OU.

---

### Legacy flat configuration

The legacy flat format remains supported:

```json
{
    "TierMappings": {
        "Tier2": {
            "gpos": [
                "Applocker-Enabled"
            ]
        }
    }
}
```

---

### GPO Categories

The default configuration groups policies into categories.

#### AllComputers

Applies to:

* Domain Controllers
* Servers
* Workstations

#### ServersOnly

Server-specific security policies.

#### WorkstationsOnly

Workstation security policies such as:

* BitLocker
* AppLocker
* Exploit Guard
* LAPS

#### UsersSide

User-context security policies such as:

* Screen lock
* WPAD restrictions
* Proxy lockdown

---

### Idempotence

ADHardened checks existing GPO links before making changes.

Re-running the deployment is therefore safe.

The final summary reports:

* Newly linked GPOs
* Already linked GPOs
* Missing GPOs
* Missing OUs
* Failed operations

---

<a id="advanced-ad-hardening"></a>

## 🛡️ Advanced AD Hardening

Advanced hardening features are disabled by default.

Review and enable each feature individually.

| Function                           | Purpose                                                           | Potential Risk                                              |
| ---------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- |
| `SetTierOUDelegation`              | Creates tier admin groups and applies OU ACL delegation           | Incorrect delegation may cause administrative access issues |
| `NewTier0AuthenticationPolicySilo` | Creates and configures a Tier 0 Authentication Policy Silo        | Enforce mode can block authentication                       |
| `LockPreWindows2000Group`          | Removes members from the Pre-Windows 2000 Compatible Access group | Legacy applications may stop working                        |
| `GetPrivilegedGroupAudit`          | Audits privileged group membership                                | Read-only operation                                         |
| `SetTier0AccountSensitive`         | Sets `AccountNotDelegated` on Tier 0 accounts                     | Kerberos delegation may stop working intentionally          |

---

### Authentication Policy Silo

All silo parameters are stored in:

```text
Config/Silo_config.json
```

Example:

```json
{
    "PolicyName": "Tier0-AuthPolicy",
    "SiloName": "Tier0-Silo",
    "Mode": "Audit",
    "TGTLifetimeMinutes": 45,
    "Members": {
        "Users": [
            "t0-admin1",
            "t0-admin2"
        ],
        "Computers": [
            "DC01$",
            "DC02$",
            "PAW-T0-01$"
        ],
        "Services": []
    }
}
```

#### Audit mode

The policy and silo are created but not enforced.

Monitor relevant Domain Controller events before enabling enforcement.

#### Enforce mode

Non-members may be blocked from authenticating to protected resources.

Only enable after validating the impact in your environment.

Re-running the function is safe:

* Existing policies are updated.
* Existing silos are updated.
* Member assignment is additive.
* Existing members are not automatically removed.

---

### Manual cleanup helper

`Remove-PrivilegedGroupMember` is intentionally not connected to the main orchestrator.

Audit first:

```powershell
Import-Module .\Modules\ADHardening.psm1

Get-PrivilegedGroupAudit `
    -ReportPath .\logs\audit.json
```

Dry-run a removal:

```powershell
Remove-PrivilegedGroupMember `
    -GroupName 'Domain Admins' `
    -MemberSamAccountName 'jdoe' `
    -WhatIf
```

Perform the removal:

```powershell
Remove-PrivilegedGroupMember `
    -GroupName 'Domain Admins' `
    -MemberSamAccountName 'jdoe'
```

The built-in `Administrator` account is protected unless:

```powershell
-AllowAdministratorRemoval
```

is explicitly provided.

---

### Recommended Hardening Order

1. Initialize the Active Directory structure.
2. Import security GPOs.
3. Apply GPOs to the appropriate tiers.
4. Enable Tier 0 account protection.
5. Lock down the Pre-Windows 2000 group after checking legacy dependencies.
6. Audit privileged groups.
7. Review the audit results.
8. Configure tier OU delegation.
9. Configure Authentication Policy Silos.
10. Start in `Audit` mode.
11. Switch to `Enforce` only after validation.

---

<a id="rollback"></a>

## ↩️ Rollback

Every run that modifies Active Directory writes **one rollback journal**:

```text
backups/journal/rollback_YYYYMMDD_HHMMSS.json
```

Each change is appended with what is needed to undo it, and the file is flushed after every entry
(it is usable even if the run crashes). `restore.ps1` replays the journal **in reverse order**, so
the newest change is undone first: links before GPOs, child OUs before parent OUs.

The `restore.ps1` script remains a separate entry point from `adhardened.ps1`.
This separation prevents mixing deployment and rollback workflows.

### Journal restore

```powershell
# List journals
.\restore.ps1 -List

# Show the content of the last journal
.\restore.ps1 -LastJournal -ShowJournal

# Preview, then restore, the last run
.\restore.ps1 -LastJournal -WhatIf
.\restore.ps1 -LastJournal

# Restore a specific run
.\restore.ps1 -JournalFile .\backups\journal\rollback_20260510_213601.json
```

Behavior:

* One confirmation for the whole journal; `-WhatIf` lists every entry that would be undone.
* A failing entry is reported and skipped, the others are still processed.
* Undone entries are marked `RestoredAt`; they are not replayed unless `-Force` is given.

| Entry type | Recorded by | Undo |
| --- | --- | --- |
| `AdAttribute` | ADSI bind, dSHeuristics, MachineAccountQuota, Kerberos encryption types | Previous value restored, or attribute cleared |
| `AdObjectCreated` | OUs, groups, authentication policy / silo | Object removed (only if it has no child) |
| `AdAcl` | Tier OU delegation, LAPS permissions | Previous security descriptor restored |
| `GroupMember` | Pre-Windows 2000 lockdown, privileged group removal | Member re-added |
| `AccountNotDelegated` | Tier 0 sensitive accounts | Previous flag restored |
| `GpoImport` | GPO import | GPO removed if created, otherwise previous content re-imported from `gpo_preimport_*` |
| `GpoLink` | GPO linking | Link removed |
| `Pso`, `PsoSubject` | Fine-grained password policies | PSO removed / previous settings restored; subject removed |
| `SiloMember` | Authentication policy silo members | Silo assignment cleared |
| `Irreversible` | Recycle Bin, LAPS schema, updated existing policy / silo | Reported as a manual action |

---

### Legacy backup types

Older runs (and `-LegacyStateBackup`) produce separate per-type backups, still restorable below.

### Available backup types

#### State backups

```text
backups/state_backup_*.json
```

Contain:

* OUs
* Groups
* GPO links
* Domain attributes
* Account delegation flags
* Authentication Policy Silos
* Privileged group membership

#### ACL backups

```text
backups/acl/acl_*.json
```

#### Pre-Windows 2000 backups

```text
backups/preWin2000_members_*.json
```

---

### List available backups

```powershell
.\restore.ps1 -List
```

---

### Preview a state restore

```powershell
.\restore.ps1 `
    -StateBackupFile .\backups\state_backup_YYYYMMDD_HHMMSS.json `
    -All `
    -WhatIf
```

The restore preview shows:

* Domain attributes to revert
* GPO links to add or remove
* Groups and OUs to delete
* Sensitive flags to revert
* Authentication Policy Silos to delete
* Privileged group membership changes

---

### Restore domain attributes

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -IncludeDomainAttrs
```

---

### Restore GPO links

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -IncludeGPOLinks
```

---

### Restore AccountNotDelegated flags

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -IncludeAccountDelegation
```

---

### Restore Authentication Policy Silos

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -IncludeSilos
```

---

### Restore privileged group membership

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -IncludePrivilegedGroups
```

---

### Restore everything

```powershell
.\restore.ps1 `
    -StateBackupFile <path> `
    -All
```

---

### Restore an OU ACL

```powershell
.\restore.ps1 `
    -ACLBackupFile .\backups\acl\acl_OU_Tier0.json
```

---

### Restore Pre-Windows 2000 group members

```powershell
.\restore.ps1 `
    -PreWin2000BackupFile .\backups\preWin2000_members_YYYYMMDD_HHMMSS.json
```

---

### Backward compatibility

Older state backup files are handled transparently.

Missing sections such as:

* `AccountNotDelegated`
* `AuthNPolicySilos`
* `PrivilegedGroups`

are safely ignored during restore.

---

### What Cannot Be Fully Reversed

Some changes are inherently irreversible or require manual remediation.

Examples:

* Active Directory Recycle Bin enablement
* LAPS schema updates
* Updates of an already existing authentication policy / silo (previous settings are not recorded)
* OUs containing user-created child objects

Rollback is therefore **best effort** and should not replace a complete Active Directory backup strategy.

---

<a id="security-considerations"></a>

## 🔐 Security Considerations

ADHardened modifies security-critical Active Directory settings.

Before using it in production:

* Test all changes in a dedicated lab.
* Review every GPO.
* Validate the impact on legacy applications.
* Maintain full System State backups of Domain Controllers.
* Use the rollback journal as a complement, not a replacement.
* Review the firewall GPO (`Firewall-Hardened`) on a pilot OU first: inbound traffic not allowed by an enabled rule is blocked.
* Review all advanced hardening functions before enabling them.
* Start Authentication Policy Silos in `Audit` mode.
* Monitor Domain Controller security logs after changes.
* Maintain a documented rollback procedure.
* Test restoration procedures regularly.

---

<a id="testing"></a>

## 🧪 Testing

ADHardened includes an offline Pester test suite.

No live Active Directory environment is required.

Run tests:

```powershell
.\Tests\Invoke-Tests.ps1
```

Run tests with CI-compatible NUnit XML output:

```powershell
.\Tests\Invoke-Tests.ps1 -CI
```

Results are written to:

```text
Tests/TestResults.xml
```

The test runner automatically installs Pester 5 or later if required.

---

<a id="roadmap"></a>

## 📝 Roadmap

### Completed

* [x] Centralized logging
* [x] Preflight validation
* [x] PowerShell 7 compatibility fallback
* [x] `-WhatIf` support
* [x] `-DryRun` support
* [x] AD state baseline capture
* [x] Best-effort rollback
* [x] Tiered OU structure
* [x] Tier-specific GPO linking
* [x] OU and group ACL delegation
* [x] Authentication Policy Silos
* [x] Privileged group auditing
* [x] Pre-Windows 2000 group lockdown
* [x] Tier 0 account protection
* [x] Offline Pester test suite
* [x] Modular PowerShell architecture
* [x] Granular GPO linking per sub-OU
* [x] State restore for hardening changes
* [x] `-ReportOnly` mode with HTML / CSV / JSON report and compliance score
* [x] Fine-Grained Password Policies (PSO)
* [x] Firewall, WinRM and legacy feature removal GPOs
* [x] Single rollback journal per run

### Planned

* [ ] GitHub Actions CI pipeline
* [ ] PSScriptAnalyzer integration
* [ ] Automated Pester execution
* [ ] Extended hybrid Active Directory support
* [ ] Additional security baseline profiles
* [ ] Per-machine posture report (local state of firewall, WinRM, SMBv1, PowerShell 2.0)
* [ ] Additional Tier 0 protection controls

---

## Project Status

**ADHardened** is an Active Directory security automation framework designed to help organizations deploy a structured, tiered, and hardened Active Directory environment.

It should be considered a security automation framework and reference implementation.

Always validate its behavior against your own:

* Active Directory architecture
* Security requirements
* Legacy applications
* Compliance requirements
* Operational processes

---

## License

See [`LICENSE`](LICENSE).

---

**ADHardened — Harden Active Directory. Defend the Domain.**
