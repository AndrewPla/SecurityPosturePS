# Securing PowerShell: A Comprehensive Reference

_A companion guide to the "Securing PowerShell from the Ground Up" talk by Andrew Pla and Jake Hildreth. Use this as a reference, a checklist, or a launchpad for going deeper on any of the features covered._

---

## How to use this document

PowerShell is one of the most powerful administrative tools on Windows. It's also one of the most abused by attackers. This document walks through the security features that ship with PowerShell, what they actually do, where they're configured, and what the security community has learned about them through real-world use.

Each feature section includes:

- **What it does** in plain English
- **Registry path** if applicable
- **Microsoft docs** for authoritative reference
- **Three security blogs** that go deeper or show how the feature relates to real attacks
- **Best practices** based on what defenders have learned

At the end you'll find ten attack retrospectives that involved PowerShell, with notes on how logging and the features in this guide either helped detect the attack or could have.

---

## A note on AppLocker vs WDAC in 2026

Before diving into individual features, one piece of context you'll see referenced throughout this document: **Microsoft now officially recommends WDAC (App Control for Business) over AppLocker for new deployments.** From their docs:

> "When choosing between App Control or AppLocker, we recommend that you implement application control using App Control for Business rather than AppLocker. Microsoft is no longer investing in AppLocker."

AppLocker still receives security fixes but won't get new features. WDAC operates deeper in the Windows security stack (kernel-level code integrity) and is the path forward. That said, AppLocker is simpler to deploy and still widely used. Both can enforce Constrained Language Mode in PowerShell. This document covers both honestly.

**Reference:** [Microsoft Learn — Use App Control to secure PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)

---

# The Features

## 1. Script Block Logging

**What it does:** Records the actual content of PowerShell script blocks as they execute. Captures the de-obfuscated version of code regardless of how it was disguised on the way in (base64, string concatenation, Invoke-Expression wrappers, etc.). Events are written to the Windows Event Log via ETW.

**Event ID:** 4104 (content), 4105 (invocation start, deep logging only), 4106 (invocation stop, deep logging only)

**Registry path (Windows PowerShell 5.1):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

**Registry path (PowerShell 7):**
```
HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging
```

**Values:**
- `EnableScriptBlockLogging` = 1 (basic)
- `EnableScriptBlockInvocationLogging` = 1 (deep)

**Microsoft docs:** [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)

**Security blogs:**
- [PowerShell ♥ the Blue Team — Lee Holmes, Microsoft](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) — the canonical post on why this feature exists and the design philosophy behind it
- [Splunk — PowerShell Detections, Threat Research Release](https://www.splunk.com/en_us/blog/security/powershell-detections-threat-research-release-august-2021.html) — practical detection patterns built on top of 4104 events
- [CyberDefenders — Why Logging PowerShell Activity Matters](https://cyberdefenders.org/blog/why-logging-powershell-activity-matters-a-soc-analysts/) — SOC analyst perspective on what to actually do with the logs

**Best practices:**
- Enable both basic and deep logging on production systems forwarded to a SIEM
- Configure both Windows PowerShell AND PowerShell 7 — they use separate registry paths
- Forward to a SIEM so attackers can't tamper with local logs
- An attacker's attempt to disable script block logging is itself logged before the change takes effect
- Combine with Module Logging and Transcription for full coverage

---

## 2. Module Logging

**What it does:** Logs pipeline execution events for specified modules. Captures cmdlet usage, parameters, and outputs. More verbose than script block logging but less informative on the actual code.

**Event ID:** 4103

**Registry path (Windows PowerShell 5.1):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

**Registry path (PowerShell 7):**
```
HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ModuleLogging
```

**Values:**
- `EnableModuleLogging` = 1
- `ModuleNames` = `*` (or specific modules)

**Microsoft docs:** [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)

**Security blogs:**
- [Mandiant — Malicious PowerShell Detection via Machine Learning](https://mandiant.com/resources/blog/malicious-powershell-detection-via-machine-learning) — shows how module logging data feeds into ML detection pipelines
- [Sumo Logic — PowerShell and Fileless Attacks](https://www.sumologic.com/blog/powershell-and-fileless-attacks) — module logging as part of fileless attack detection
- [Elastic — PowerShell Module Configuration](https://www.elastic.co/guide/en/beats/winlogbeat/8.19/winlogbeat-module-powershell.html) — operationalizing module logs in a SIEM

**Best practices:**
- Set `ModuleNames` to `*` for full coverage in security-sensitive environments
- Module logging generates significantly more events than script block logging — plan storage accordingly
- Useful for catching cmdlet-level abuse that doesn't generate distinct script blocks

---

## 3. Transcription

**What it does:** Writes every PowerShell session to a text file, including all input and output. Essentially a `script` command for PowerShell.

**Event ID:** No event log entries — output is files on disk

**Registry path (Windows PowerShell 5.1):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
```

**Registry path (PowerShell 7):**
```
HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription
```

**Values:**
- `EnableTranscripting` = 1
- `EnableInvocationHeader` = 1 (recommended)
- `OutputDirectory` = path (write to a write-only network share for tamper resistance)

**Microsoft docs:** [about_Logging_Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)

**Security blogs:**
- [Cisco — The Power of Logging in Incident Response](https://blogs.cisco.com/security/the-power-of-logging-in-incident-response) — uses transcription to detect Mimikatz in a real lab scenario
- [Let's Defend — Detecting Malicious PowerShell Scripts](https://letsdefend.io/blog/detecting-malicious-powershell-scripts) — how transcription fits into a layered detection strategy
- [ManageEngine — PowerShell Empire Cyberattacks](https://www.manageengine.com/log-management/cyber-security/powershell-empire-cyberattacks.html) — transcription's role in catching post-exploitation tooling

**Best practices:**
- Write transcripts to a centralized share that admins/attackers can't easily tamper with
- Combine with `EnableInvocationHeader` so each entry timestamps and identifies the user
- Don't rely on transcription alone — it can be disabled by a determined attacker
- Useful for forensics; less useful for real-time detection (no event log integration)

---

## 4. AMSI (Antimalware Scan Interface)

**What it does:** A Windows API that lets PowerShell pass script content to your installed antivirus engine for inspection before execution. Catches signature-based detections of known malicious code.

**Event ID:** Varies by AV vendor

**Registry path:** Controlled by Windows Defender or the installed AV product. Not directly user-configured in PowerShell.

**Microsoft docs:** [Antimalware Scan Interface](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)

**Security blogs:**
- [MDSec — AppLocker CLM Bypass via COM](https://www.mdsec.co.uk/2018/09/applocker-clm-bypass-via-com/) — attacker perspective on AMSI bypasses
- [Mandiant — Malicious PowerShell Detection](https://mandiant.com/resources/blog/malicious-powershell-detection-via-machine-learning) — discusses AMSI's role in defense layering
- [amsi.fail](https://amsi.fail/) — collection of AMSI bypass techniques (useful for understanding what defenders are up against)

**Best practices:**
- AMSI is one layer of defense, not the only one
- Effectiveness depends entirely on your AV/EDR vendor's signatures
- Fragmented payloads (split across variables) can evade AMSI but get caught by script block logging
- A clean AMSI scan does not mean the script is safe — it means no signature matched

---

## 5. Constrained Language Mode (CLM)

**What it does:** Restricts PowerShell to a subset of the language that excludes most .NET interop, COM access, and dangerous types. Designed to allow administrative scripting while blocking attacker tooling that depends on direct .NET API access.

**Detection via:** `$ExecutionContext.SessionState.LanguageMode`

**How it's enforced:** Either by AppLocker/WDAC policy (PowerShell detects the policy and engages CLM automatically) or by setting the `__PSLockdownPolicy` environment variable for testing.

**Microsoft docs:** [about_Language_Modes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes)

**Security blogs:**
- [Patch My PC — Windows 11 24H2: AppLocker Script Enforcement Not Working](https://patchmypc.com/blog/windows-11-24h2-applocker-powershell-constrained-language-broken/) — recent bug that broke CLM enforcement on Server 2025/Win11 24H2 and the May 2025 fix
- [4sysops — Mitigating PowerShell Risks with CLM](https://4sysops.com/archives/mitigating-powershell-risks-with-constrained-language-mode/) — how CLM actually works under the hood
- [Microsoft PowerShell Team — Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) — official explanation of how CLM engages

**Best practices:**
- Enforce via WDAC for new deployments, AppLocker for legacy
- Test thoroughly in audit mode before enforcing — CLM breaks many legitimate scripts
- Local administrators bypass AppLocker's default rules — test CLM enforcement as a standard user
- On Windows Server 2025 / Windows 11 24H2, verify the May 2025 security update is installed or CLM enforcement via AppLocker won't work correctly
- CLM alone isn't enough — combine with PowerShell 2.0 disabled to prevent downgrade attacks

---

## 6. AppLocker

**What it does:** Application allowlisting/blocklisting feature that controls which executables, scripts, and installers can run based on path, publisher, or file hash. PowerShell detects AppLocker enforcement and engages CLM accordingly.

**Registry path (rules):**
```
HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2
```

**Service:** Application Identity (`AppIDSvc`) must be running

**Microsoft docs:** [AppLocker overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-overview)

**Security blogs:**
- [Splunk — Mastering Microsoft AppLocker, Part 1](https://www.splunk.com/en_us/blog/security/deploy-test-monitor-mastering-microsoft-applocker-part-1.html) — practical deployment from a SIEM vendor's perspective
- [P0w3rsh3ll — AppLocker and PowerShell: How They Tightly Work Together](https://p0w3rsh3ll.wordpress.com/2019/03/07/applocker-and-powershell-how-do-they-tightly-work-together/) — deep dive on the integration
- [Industrial Monitor Direct — Restrict PowerShell to Admins](https://industrialmonitordirect.com/blogs/knowledgebase/limiting-powershell-access-for-non-admin-users-via-gpo) — modern enterprise perspective including AppLocker bypass realities

**Best practices:**
- **Microsoft no longer invests new features in AppLocker** — use WDAC for new deployments
- Default rules are intentionally permissive (Everyone can run from `%WINDIR%` and `%PROGRAMFILES%`)
- Local administrators bypass AppLocker by default — adjust rules if you want admin restrictions too
- Always start in Audit mode, monitor for breakage, then move to Enforce
- AppLocker can be bypassed by renamed executables, alternate paths, or DLL hijacking — defense in depth still required

---

## 7. WDAC (Windows Defender Application Control / App Control for Business)

**What it does:** Kernel-level code integrity policy enforcement. Controls which drivers, scripts, and applications can run. More secure and feature-rich than AppLocker. Engages CLM in PowerShell for untrusted code while allowing trusted code to run in FullLanguage mode.

**Microsoft docs:** [App Control for Business overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/wdac)

**Microsoft docs (PowerShell-specific):** [Use App Control to secure PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)

**Server 2025 deployment:** [Configure App Control on Windows Server 2025 via OSconfig](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business)

**Security blogs:**
- [Patch My PC — How to use App Control for Business](https://patchmypc.com/blog/how-use-app-control-business/) — practical deployment walkthrough
- [Petri — How to Deploy Microsoft Defender Application Control](https://petri.com/how-to-deploy-microsoft-defender-application-control-previously-wdac/) — covers AppLocker→WDAC migration
- [beierle.win — WDAC: Powerful and Persistent Host-Based Protection](https://beierle.win/2024-08-09-WDAC/) — wizard-based deployment walkthrough

**Best practices:**
- Microsoft's recommended choice over AppLocker
- Audit mode is non-negotiable for initial deployment — enforcing prematurely can brick a machine
- Multiple policy support since Windows 10 1903 — use base + supplemental policies
- For Server 2025, deploy via OSconfig with Microsoft-defined default policies as a starting point
- Plan for ongoing policy maintenance — applications and updates change often
- Pairs well with code signing for the highest-trust scenarios

---

## 8. JEA (Just Enough Administration)

**What it does:** Role-based access control for PowerShell remoting. Lets you create constrained PowerShell endpoints where specific users can run only specific commands with specific parameters, often under a virtual admin account. Users don't get full admin rights — they get just enough to do their specific job.

**Microsoft docs:** [JEA overview](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview)

**Components:**
- `.psrc` files (role capabilities) — what commands are allowed
- `.pssc` files (session configurations) — who gets which role
- `Register-PSSessionConfiguration` — deploys the endpoint

**Security blogs:**
- [Simple Talk — PowerShell JEA: Role Capabilities and Constrained Endpoints](https://www.red-gate.com/simple-talk/sysadmin/powershell/powershell-just-enough-administration/) — deep technical overview
- [SID-500 — Implementing JEA Step-by-Step](https://sid-500.com/2018/02/11/powershell-implementing-just-enough-administration-jea-step-by-step/) — practical walkthrough with screenshots
- [Automox — Windows Administration with PowerShell: JEA](https://www.automox.com/blog/windows-administration-with-powershell-13-just-enough-administration) — accessible introduction to the philosophy

**Best practices:**
- Powerful but underused — adoption requires upfront role-modeling work
- Pairs naturally with transcription (each JEA session is logged automatically)
- Use virtual accounts so user credentials never get admin rights
- Deploy via DSC for consistency across many endpoints
- Test thoroughly — getting role capabilities wrong either blocks legitimate work or grants too much access

---

## 9. PowerShell 2.0 Removal

**What it does:** Removes the legacy PowerShell 2.0 engine from the system. PS 2.0 predates almost every PowerShell security feature — no script block logging, no AMSI, no CLM, no AppLocker/WDAC integration. Attackers downgrade to it specifically to bypass logging and CLM.

**Check command:**
```powershell
Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

**Disable command:**
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

**Microsoft docs:** [Removing the Windows PowerShell 2.0 Engine](https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/install/removing-the-windows-powershell-2.0-engine)

**Security blogs:**
- [NSA/CISA — Keeping PowerShell: Security Measures to Use and Embrace](https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF) — government guidance recommending PS 2.0 removal
- [Mondoo — New Security Guidelines for PowerShell](https://blog.mondoo.com/security-recommendations-for-powershell) — coverage of the NSA guidelines and what they mean
- [ReliaQuest — PowerShell Security Best Practices](https://reliaquest.com/blog/powershell-security-best-practices/) — modern enterprise context for the PS2 problem

**Best practices:**
- Disabled by default in Windows 11 and supported Server OSes since August 2025
- **EOL machines and older Server versions may still have it enabled** — audit your environment
- Removal is non-disruptive in modern environments (almost nothing legitimate still needs PS 2.0)
- Without removing PS 2.0, all your other PowerShell hardening can be bypassed by an attacker running `powershell.exe -version 2`

---

## 10. Execution Policy

**What it does:** Controls whether PowerShell scripts can run by default and whether they need to be signed. Often misunderstood — it's a safety feature to prevent accidental execution, **not a security boundary**.

**Microsoft docs:** [about_Execution_Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)

**Microsoft's own statement:**
> "The PowerShell execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts. **This feature helps prevent the execution of malicious scripts. It is not a security system that restricts user actions.**"

**Security blogs:**
- [NetSPI — 15 Ways to Bypass the PowerShell Execution Policy](https://www.netspi.com/blog/technical-blog/network-pentesting/15-ways-to-bypass-the-powershell-execution-policy/) — documents the many trivial bypasses
- [PowerShell ♥ the Blue Team — Lee Holmes](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) — Microsoft's perspective on what execution policy actually does
- [Mandiant — Malicious PowerShell Detection](https://mandiant.com/resources/blog/malicious-powershell-detection-via-machine-learning) — notes attackers regularly use `-ExecutionPolicy Bypass`

**Best practices:**
- Set to `RemoteSigned` or `AllSigned` on production systems
- **Do not rely on this as a security control** — it's a guardrail against mistakes
- WDAC + CLM is the actual security boundary
- An attacker setting `-ExecutionPolicy Bypass` is a useful detection signal in logs

---

## 11. Code Signing

**What it does:** PowerShell can require scripts to be cryptographically signed before they'll run. Combined with `AllSigned` execution policy or WDAC trust policies, this provides strong assurance of script origin and integrity.

**Microsoft docs:** [about_Signing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing)

**Security blogs:**
- [Microsoft PowerShell Team — Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) — signed scripts run in FullLanguage under WDAC even when CLM is enforced
- [Medium — Create and Deploy Signed WDAC Policy](https://spynetgirl.medium.com/create-and-deploy-signed-wdac-policy-f720e3a98d08) — operationalizing code signing with WDAC
- [Splunk — Mastering AppLocker](https://www.splunk.com/en_us/blog/security/deploy-test-monitor-mastering-microsoft-applocker-part-1.html) — publisher rules are a form of code signing trust

**Best practices:**
- Useful for environments that distribute internal scripts at scale
- Requires PKI infrastructure — not lightweight to deploy
- More valuable when combined with WDAC than with execution policy alone
- Worth it for high-security environments, overkill for most

---

# Modern Best Practices Summary

If you're starting from scratch in 2026, here's the priority order based on effort-to-value ratio:

| # | Feature | Effort | Value |
| --- | --- | --- | --- |
| 1 | **Script Block Logging (basic + deep)** | Low | Very High |
| 2 | **Module Logging** | Low | High |
| 3 | **Transcription to central share** | Low | Medium |
| 4 | **Disable PowerShell 2.0** | Low | High |
| 5 | **Execution Policy = RemoteSigned** | Low | Low (safety, not security) |
| 6 | **WDAC base policy in Audit mode** | Medium | High |
| 7 | **WDAC enforcement mode** | High | Very High |
| 8 | **JEA for privileged remoting** | High | Very High |
| 9 | **Code signing infrastructure** | High | Medium-High |

**The four quick wins anyone can do today:** enable script block logging, enable module logging, disable PowerShell 2.0, set execution policy. That's a Monday morning checklist.

**The harder but more valuable work:** WDAC and JEA. These require planning, testing, and ongoing maintenance, but they're where the real security boundaries live.

---

# Real-World Attack Retrospectives

PowerShell shows up in nearly every modern attack involving Windows. These ten case studies walk through real incidents — what attackers did, what defenders saw (or didn't), and how PowerShell's security features either helped or could have.

## 1. SolarWinds (2020) — The Supply Chain Attack

The SUNBURST backdoor was inserted into legitimate SolarWinds Orion builds. After initial access, attackers used PowerShell extensively for credential theft, lateral movement, and creating remote scheduled tasks.

[Zero Networks — Examining the SolarWinds Supply Chain Attack](https://zeronetworks.com/blog/examining-solarwinds-supply-chain-attack)

**Logging angle:** Attackers blended in by using legitimate PowerShell remoting and scheduled task patterns. Script block logging would have captured the actual commands, but distinguishing them from legitimate admin activity required behavioral analysis and baselining. The attackers operated undetected for nearly a year — visibility alone wasn't enough, but it would have helped.

## 2. Kaseya (2021) — REvil Ransomware via MSP

REvil exploited Kaseya VSA to deploy ransomware downstream to 1,500+ MSP customer organizations. The attack chain included PowerShell scripts for both initial deployment and Kaseya's own incident response (a PowerShell script was released to detect compromised clients).

[Brandefense — Understanding Supply Chain Attack Tactics](https://brandefense.io/blog/understanding-supply-chain-attack-tactics-with-case-study/)

**Logging angle:** The deployment scripts used base64-encoded commands and `-EncodedCommand`. Script block logging would have caught the decoded content. Many affected organizations had no PowerShell logging enabled at all.

## 3. NotPetya (2017) — Wiper Disguised as Ransomware

Spread through hijacked updates of Ukrainian accounting software M.E.Doc. Used PowerShell alongside Mimikatz-based credential harvesting and SMB-based propagation (EternalBlue).

[Beyond Identity — Software Supply Chain Attacks: SolarWinds, Kaseya, NotPetya](https://www.beyondidentity.com/resource/software-supply-chain-attack-methods-behind-solarwinds-kaseya-and-notpetya-and-how-to-prevent-them)

**Logging angle:** The Mimikatz invocation patterns are well-known signatures. AMSI catches some variants. Script block logging catches all of them. Most NotPetya victims had neither enabled.

## 4. Akira Ransomware Attack Analysis

Real-world Akira attack where attackers used PowerShell to create a Cloudflare Tunnel for persistent remote access, then deployed Advanced IP Scanner to map the network before pushing ransomware.

[ThreatDown — The Anatomy of an Akira Ransomware Attack](https://www.threatdown.com/blog/anything-but-science-fiction-the-anatomy-of-an-akira-ransomware-attack/)

**Logging angle:** Critically, the victim had **excluded PowerShell and cmd.exe from monitoring**. This is a recurring theme. Defenders disable PowerShell logging because of noise, then can't see the attack when it happens. Script block logging would have shown every command in the kill chain.

## 5. INTERLOCK Ransomware Operations

Recent ransomware operations using PowerShell for user profiling, group enumeration, and reconnaissance. Notably included `Start-Sleep` jitter to evade rapid-fire command detection.

[Mandiant — Ransomware TTPs in a Shifting Threat Landscape](https://cloud.google.com/blog/topics/threat-intelligence/ransomware-ttps-shifting-threat-landscape)

**Logging angle:** Time-based evasion only works if defenders are looking for rapid execution patterns. Content-based detection via script block logging catches the actual commands regardless of timing.

## 6. APT32 (OceanLotus) — Vietnam-Linked Threat Actor

Long-running campaign documented by FireEye/Mandiant using PowerShell at multiple stages of the kill chain. Demonstrated extensive use of `-NoProfile`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass`.

[Mandiant — Malicious PowerShell Detection via Machine Learning](https://mandiant.com/resources/blog/malicious-powershell-detection-via-machine-learning)

**Logging angle:** The argument patterns themselves are detection signals. Every `-ExecutionPolicy Bypass` is a useful alert. Script block logging captures the parameters and the script content in the same event.

## 7. PowerShell Empire C2 Frameworks

Open-source post-exploitation framework that became a template for adversary tooling. Operates entirely in memory, traditionally evades file-based AV, and uses common PowerShell idioms to blend in.

[HoldMyBeer — Intro to Threat Hunting with PowerShell Empire](https://holdmybeersecurity.com/2020/01/23/part-2-intro-to-threat-hunting-understanding-the-attacker-mindset-with-powershell-empire-and-the-mandiant-attack-lifecycle/)

**Logging angle:** Empire's stager and agent code are well-known. AMSI catches the default stagers. Script block logging captures everything Empire does after launch. Memory forensics is the fallback when logging isn't enabled.

## 8. Invoke-Mimikatz In-Memory Credential Theft

The classic credential theft technique — loading Mimikatz into PowerShell memory without ever writing to disk. Detected by Elastic, Splunk, Defender, and basically every modern SIEM rule library.

[Cisco — The Power of Logging in Incident Response](https://blogs.cisco.com/security/the-power-of-logging-in-incident-response)
[Elastic — Potential Invoke-Mimikatz PowerShell Script](https://www.elastic.co/guide/en/security/8.19/potential-invoke-mimikatz-powershell-script.html)

**Logging angle:** This is the prototype "logging is everything" scenario. Without script block logging or transcription, an Invoke-Mimikatz attack leaves zero disk artifacts. With logging, every byte of the Mimikatz code is in your logs.

## 9. SolarWinds Web Help Desk Active Exploitation (2026)

Microsoft Defender Research identified ongoing exploitation of SolarWinds WHD where attackers used PowerShell + BITS to download payloads, then installed legitimate RMM tools (Zoho ManageEngine) for persistence.

[Microsoft Security — Active Exploitation of SolarWinds Web Help Desk](https://www.microsoft.com/en-us/security/blog/2026/02/06/active-exploitation-solarwinds-web-help-desk/)

**Logging angle:** Attackers increasingly use legitimate tools (RMM, BITS, signed binaries) for persistence to avoid signature-based detection. Behavioral detection requires baselining — which requires having the logs in the first place.

## 10. Fileless PowerShell + Mimikatz via Atomic Red Team

Detection engineering walkthrough showing how Atomic Red Team's MITRE-aligned tests simulate fileless attacks, and how to build detection logic in a SIEM around them. Maps directly to MITRE T1059.001 (PowerShell), T1003 (Credential Dumping), and T1566.001 (Phishing).

[Medium — From Simulation to Detection: Fileless PowerShell & Mimikatz](https://medium.com/@Mohamed_Elfayoumy/from-simulation-to-detection-fileless-powershell-mimikatz-attacks-using-atomic-red-team-mitre-459e3624e0ac)

**Logging angle:** This is the practical playbook. Atomic Red Team's T1059.001 tests are designed exactly to validate that your PowerShell logging and detection works. Run them, confirm you see them in your SIEM, iterate.

---

# The Big Picture

A few patterns emerge across these retrospectives:

**Logging is the floor, not the ceiling.** Every retrospective where defenders had any chance of catching the attack early involved PowerShell logging in some form. Every retrospective where defenders couldn't see what happened involved organizations that either hadn't enabled it or had explicitly excluded PowerShell from monitoring.

**Behavioral baselining matters more than signatures.** Modern attackers use legitimate tools (PowerShell remoting, scheduled tasks, signed RMM software) because signature-based detection misses them. You need to know what normal looks like in your environment.

**Defense in depth is the only path that actually works.** No single feature catches everything. Script block logging catches what AMSI misses. WDAC catches what AppLocker misses. JEA limits what compromised credentials can do. Disabling PS 2.0 prevents downgrade attacks that bypass everything else.

**The features exist. Most environments just haven't turned them on.** That's the recurring lesson. The hard part isn't building detection — it's enabling visibility.

---

# References & Further Reading

## Primary references

- [NSA/CISA — Keeping PowerShell: Security Measures to Use and Embrace](https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF)
- [Microsoft Learn — PowerShell Security Features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
- [Microsoft Learn — Use App Control to secure PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [PowerShell ♥ the Blue Team — Lee Holmes](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)

## Companion talks worth watching

- [PowerShell Security: A Journey Through Time — Miriam Wiesner & Anam Navied (PSConfEU 2025)](https://www.youtube.com/watch?v=i5hbvcT26Zc)
- [Practical PowerShell Empowerment For Protectors — Miriam Wiesner (PSConfEU 2024)](https://www.youtube.com/watch?v=JgqbR-7O7TI)
- [PowerShell Security — Friedrich Weinmann (PSConfEU 2022)](https://www.youtube.com/watch?v=M261YjSKj4w)
- [Derbycon 2016 Keynote — Jeffrey Snover & Lee Holmes](https://www.youtube.com/watch?v=BMreZZ1cgFI)

## Tools to test against

- [Atomic Red Team — T1059.001 PowerShell tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md)
- [Invoke-Obfuscation by Daniel Bohannon](https://github.com/danielbohannon/Invoke-Obfuscation)
- [Get-PSSecurity (coming at PSConfEU 2026)](https://github.com/) — Andrew Pla & Jake Hildreth

---

_Built and maintained by Andrew Pla. Find more at [andrewpla.tech](https://andrewpla.tech) or on [The PowerShell Podcast](https://powershellpodcast.podbean.com/). Co-developed for the "Securing PowerShell from the Ground Up" talk with Jake Hildreth._
