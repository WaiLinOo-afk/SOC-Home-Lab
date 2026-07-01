# SOC Home Lab: Splunk SIEM with MITRE ATT&CK Detection

> A fully functional Security Operations Center (SOC) home lab built to simulate real-world threat detection workflows using Splunk Enterprise as the SIEM, Sysmon for endpoint telemetry, and Atomic Red Team for adversary emulation mapped to MITRE ATT&CK.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Lab Architecture](#lab-architecture)
3. [Environment Setup](#environment-setup)
4. [Step 1 — Splunk Enterprise Installation](#step-1--splunk-enterprise-installation)
5. [Step 2 — Sysmon Endpoint Monitoring](#step-2--sysmon-endpoint-monitoring)
6. [Step 3 — Splunk Universal Forwarder (Windows)](#step-3--splunk-universal-forwarder-windows)
7. [Step 4 — Splunk Universal Forwarder (Kali Linux)](#step-4--splunk-universal-forwarder-kali-linux)
8. [Step 5 — Attack Simulations](#step-5--attack-simulations)
9. [Step 6 — SOC Dashboard](#step-6--soc-dashboard)
10. [Detection Rules Summary](#detection-rules-summary)
11. [Known Issues & Limitations](#known-issues--limitations)
12. [Skills Demonstrated](#skills-demonstrated)
13. [References](#references)

---

## Project Overview

This home lab replicates a minimal but functional enterprise SOC environment. The primary objectives are:

- **Collect** endpoint and network telemetry from both a Windows victim machine and a Kali Linux attacker
- **Detect** attacker behaviors mapped to the [MITRE ATT&CK framework](https://attack.mitre.org/) using Splunk SPL queries
- **Analyze** why certain detections succeed or fail, and understand the underlying Windows event logging mechanics

Five MITRE ATT&CK techniques are simulated using Atomic Red Team, plus one network reconnaissance technique from Kali:

| Technique | Name | Tactic |
|-----------|------|--------|
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | Credential Access |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | Execution |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | Persistence |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote Services: SMB/Windows Admin Shares | Lateral Movement |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery (Nmap) | Discovery |

---

## Lab Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        VMware Workstation                         │
│                                                                   │
│  ┌──────────────────────────────┐  ┌───────────────────────────┐ │
│  │   Windows 11 VM              │  │  Kali Linux VM            │ │
│  │   192.168.56.130             │  │  192.168.56.129           │ │
│  │                              │  │                           │ │
│  │  ┌───────────────────────┐   │  │  ┌─────────────────────┐ │ │
│  │  │ Splunk Enterprise     │   │  │  │ Splunk UF           │ │ │
│  │  │ SIEM (port 8000)      │◄──┼──┼──┤ Nmap / smbclient    │ │ │
│  │  │ Receiver port 9997    │   │  │  │ Brute Force Tools   │ │ │
│  │  └───────────────────────┘   │  │  └─────────────────────┘ │ │
│  │            ▲                 │  └───────────────────────────┘ │
│  │  ┌─────────┴─────────────┐   │                               │
│  │  │ Splunk Universal FWD  │   │                               │
│  │  │ Sysmon v15.20         │   │                               │
│  │  │ SwiftOnSecurity config│   │                               │
│  │  └───────────────────────┘   │                               │
│  └──────────────────────────────┘                               │
└──────────────────────────────────────────────────────────────────┘
```

**Data flow:**

1. Sysmon captures endpoint events (process creation, network connections, registry changes) on the Windows VM and writes them to the Windows Event Log channel `Microsoft-Windows-Sysmon/Operational`.
2. Splunk Universal Forwarder on Windows reads Sysmon events + Windows Security/System logs and forwards them to Splunk Enterprise on port 9997.
3. Splunk Universal Forwarder on Kali forwards Linux logs (dpkg, apache2, vmware-network) to the same Splunk indexer.
4. Splunk Enterprise indexes all data and serves the Web UI on port 8000.

---

## Environment Setup

| Component | Details |
|-----------|---------|
| SIEM | Splunk Enterprise 10.4.0 |
| Windows VM (Victim/Monitor) | Windows 11 — 192.168.56.130 |
| Kali Linux VM (Attacker) | Kali Linux — 192.168.56.129 |
| Virtualization | VMware Workstation |
| Log Forwarder | Splunk Universal Forwarder v10.4.0 |
| Endpoint Monitoring | Sysmon v15.20 with SwiftOnSecurity config |
| Splunk Web UI | http://localhost:8000 |
| Receiving Port | 9997 |

---

## Step 1 — Splunk Enterprise Installation

### 1.1 Installation

Downloaded the Windows `.msi` installer from [splunk.com](https://www.splunk.com) and installed Splunk Enterprise on the Windows VM (192.168.56.130) with default settings.

### 1.2 Create Indexes

After logging in at `http://localhost:8000`, navigate to **Settings → Indexes → New Index** and create the following three indexes:

| Index Name | Purpose |
|------------|---------|
| `wineventlog` | Windows Security and System event logs |
| `sysmon` | Sysmon endpoint telemetry (process creation, network, registry) |
| `syslog` | Kali Linux logs (dpkg, apache, vmware-network) |

Separate indexes improve SPL query performance significantly — `index=sysmon` is far faster than `index=* sourcetype=sysmon`. In production environments, proper index design is a key part of Splunk capacity planning.

### 1.3 Configure Receiving Port

Navigate to **Settings → Forwarding and Receiving → Configure Receiving → New Receiving Port**. Set port to `9997`.

> ⚠️ **Note:** This port must be open on the Windows Firewall for Universal Forwarders to send data. If events stop arriving, verify this rule first.


---

## Step 2 — Sysmon Endpoint Monitoring

[Sysmon (System Monitor)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) is a Windows system service and device driver that, once installed, remains resident across reboots to monitor and log system activity to the Windows Event Log. It provides process creation records with full command lines, network connections with process context, DNS queries, file creation timestamps, and registry modifications — visibility that native Windows Security auditing entirely lacks.

### 2.1 Download

- Sysmon binary: [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Configuration: [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

The SwiftOnSecurity config is a community-maintained XML ruleset that balances detection coverage against log volume. It excludes known-good processes (Windows Defender, browser update helpers) while preserving high-fidelity signals for suspicious behaviors — mirroring how production SOC teams tune their SIEM to reduce analyst fatigue.

### 2.2 Installation

Run in **PowerShell (Administrator)**:

```powershell
cd C:\Users\<username>\Downloads\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### 2.3 Verification

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

**Expected result:** Service status `Running`, EventID 1 (Process Create) events populating the log.

> **Key Sysmon EventIDs used in this lab:**
> - **EventID 1** — Process Create (image path, command line, parent process, user)
> - **EventID 3** — Network Connection (source/dest IP, port, process)
> - **EventID 11** — File Create (path, process responsible)

---

## Step 3 — Splunk Universal Forwarder (Windows)

The Splunk Universal Forwarder (UF) is a lightweight agent that collects log data and forwards it to a Splunk indexer. Unlike a full Splunk instance, it performs no indexing or searching — minimizing resource usage on the monitored endpoint.

### 3.1 Installation

Downloaded the Windows 64-bit `.msi` installer from splunk.com. During setup, the receiving indexer was set to `127.0.0.1:9997` (loopback, since Splunk Enterprise runs on the same host).

### 3.2 Configure `inputs.conf`

This file tells the forwarder **what** to collect. Location: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Security]
disabled = 0
index = wineventlog

[WinEventLog://System]
disabled = 0
index = wineventlog

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = sysmon
renderXml = true
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

The `renderXml = true` directive is critical for Sysmon: it preserves the full XML structure of events, which makes subsequent field extraction with `rex` in SPL reliable. Without it, the raw event is a truncated plain-text representation.

### 3.3 Configure `outputs.conf`

Location: `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 127.0.0.1:9997

[tcpout-server://127.0.0.1:9997]
```

### 3.4 Fix Sysmon Channel Access Issue

The Sysmon operational log channel (`Microsoft-Windows-Sysmon/Operational`) has a restrictive `channelAccess` DACL that only grants read access to `SYSTEM (SY)`, `Administrators (BA)`, and two additional built-in groups. The default `SplunkForwarder` service account runs under a limited service identity and lacks read access, causing the forwarder to silently drop all Sysmon events.

**Fix — run the forwarder as LocalSystem:**

```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

> **Production note:** The correct long-term fix in an enterprise environment is to grant read access to the specific service account using `wevtutil sl Microsoft-Windows-Sysmon/Operational /ca:"..."`. Running as LocalSystem grants excessive privilege and is a lab-only workaround.

### 3.5 Verification

```powershell
Restart-Service SplunkForwarder
```

In Splunk Search:

```spl
index=wineventlog | head 10
index=sysmon | head 10
```

Both queries should return events, confirming data is flowing.

**Evidence:**

![wineventlog index](screenshots/index%3Dwineventlog.png)
![sysmon index](screenshots/index%3Dsysmon.png)


---

## Step 4 — Splunk Universal Forwarder (Kali Linux)

### 4.1 Installation

```bash
sudo dpkg -i splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
```

### 4.2 Configure `outputs.conf`

Points the forwarder to Splunk Enterprise on the Windows VM:

```ini
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.56.130:9997

[tcpout-server://192.168.56.130:9997]
```

### 4.3 Configure `inputs.conf`

Modern Kali Linux uses `systemd-journald` instead of traditional syslog, meaning `/var/log/auth.log` and `/var/log/syslog` do not exist. Available log files were used instead:

```ini
[monitor:///var/log/dpkg.log]
index = syslog
sourcetype = linux_logs

[monitor:///var/log/apache2]
index = syslog
sourcetype = apache_logs

[monitor:///var/log/vmware-network.log]
index = syslog
sourcetype = linux_logs
```

### 4.4 Fix Windows Firewall

The Kali forwarder could not reach port 9997 on the Windows VM because the Windows Firewall blocked inbound connections by default. Add an inbound allow rule:

```powershell
New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

Verify connectivity from Kali:

```bash
nc -zv 192.168.56.130 9997
```

### 4.5 Start and Verify

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

In Splunk:

```spl
index=syslog | head 10
```
**Evidence:**
![syslog index](screenshots/index%3Dsyslog.png)

Should return events from `host=kali`, confirming cross-VM log forwarding is working.

---

## Step 5 — Attack Simulations

### 5.1 Atomic Red Team Setup

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is an open-source library of small, focused tests that replicate the specific commands, APIs, and tools used by real adversaries — each mapped to a single MITRE ATT&CK technique. It is maintained by Red Canary and is widely used by detection engineers to validate whether a SIEM actually detects the techniques it claims to.

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

> **Note:** Windows Defender will flag Atomic Red Team payloads during installation. This is expected and confirms the tools replicate real attack behavior. Add an exclusion for the lab directory:
> ```powershell
> Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
> ```

**Evidence:**

![Atomic Red Team Setup](screenshots/AtomicRedTeamSetup.png)

---

### T1003.001 — OS Credential Dumping: LSASS Memory

**Tactic:** Credential Access | **Technique:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

LSASS (Local Security Authority Subsystem Service) is the Windows process responsible for authentication. It holds cached credentials in memory — NTLM hashes, Kerberos tickets, plaintext passwords (on older systems). Attackers target LSASS memory to extract these credentials for lateral movement, privilege escalation, or pass-the-hash attacks without needing to crack passwords.

Common tools: Mimikatz, ProcDump, comsvcs.dll (`MiniDump`), pypykatz.

**Execution:**

```powershell
Invoke-AtomicTest T1003.001
```


**Result:** All sub-tests returned `Access Denied` — Windows Defender blocked execution of ProcDump, Mimikatz, comsvcs.dll, and pypykatz. However, the attempt itself was still logged by Sysmon EventID 1.

> **Key insight:** Blocked attacks still leave forensic artifacts. Sysmon EventID 1 records every process creation attempt, including those that terminate immediately with an error. A defender who only tracks successful executions will miss the majority of real-world attack activity. Prevention ≠ invisibility.

**Splunk Detection Query:**

```spl
earliest=0 index=sysmon _raw="lsass"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| where NOT like(Image, "%Photos%")
  AND NOT like(Image, "%SnippingTool%")
  AND NOT like(Image, "%PickerHost%")
| table _time, host, Image, CommandLine
| sort -_time
```

**Evidence:**

![T1003.001 Output](screenshots/T1003.001.png)
![T1003.001 Detection](screenshots/Splunk%20Sysmon%20Detection%20-%20T1003.001%20LSASS%20Memory%20Dump%20Attempt.png)


---

### T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution | **Technique:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

PowerShell is the most commonly abused interpreter in Windows environments. Its deep integration with the .NET framework and Windows APIs makes it a powerful post-exploitation tool. Attackers use encoded commands (`-EncodedCommand`), execution policy bypass flags (`-ExecutionPolicy Bypass`), and `Invoke-Expression` (`IEX`) to run malicious code while evading simple signature detection.

**Execution:**

```powershell
Invoke-AtomicTest T1059.001
```

**Result:** Multiple sub-tests executed successfully, including NTFS Alternate Data Stream access and various encoded command executions. Sub-test 17 printed output confirming execution.

**Splunk Detection Query:**

```spl
earliest=0 index=sysmon _raw="1"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| where like(lower(Image), "%powershell%")
| where like(lower(CommandLine), "%-enc%")
  OR like(lower(CommandLine), "%-bypass%")
  OR like(lower(CommandLine), "%-nop%")
  OR like(lower(CommandLine), "%iex%")
| table _time, host, Image, CommandLine, ParentImage
| sort -_time
```

**Detection logic:** The query hunts for PowerShell processes whose command-line arguments contain flags commonly used for obfuscation and policy bypass. The `ParentImage` field is particularly valuable for triage — `powershell.exe` spawned by `WINWORD.EXE`, `outlook.exe`, or `mshta.exe` is almost certainly malicious, whereas the same process spawned by `explorer.exe` requires more context.

**Evidence:**

![T1059.001 Output](screenshots/T1059.001.png)
![T1059.001 Detection](screenshots/Splunk%20Sysmon%20Detection%20-%20T1059.001%20—%20PowerShell.png)


---

### T1053.005 — Scheduled Task/Job: Scheduled Task

**Tactic:** Persistence | **Technique:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)

Scheduled tasks are a classic persistence mechanism — they survive reboots, can execute under SYSTEM-level privileges, and blend in with legitimate administrative automation. This test creates several tasks: `ATOMIC-T1053.005`, `CompMgmtBypass`, and `EventViewerBypass`. The latter two demonstrate UAC bypass by hijacking the COM object lookup of trusted Windows binaries to execute attacker-controlled code without triggering a UAC prompt.

**Execution:**

```powershell
Invoke-AtomicTest T1053.005
```

**Result:** Multiple scheduled tasks created and persisted across reboots. Calculator and Event Viewer launched as proof of execution (UAC bypass via trusted binaries).

**Troubleshooting Note:** EventCode 4698 (A scheduled task was created) was **not** logged despite explicitly enabling the relevant audit subcategory:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

This is a known limitation on Windows 11 — the audit subcategory mapping appears broken on certain builds. Sysmon process monitoring was used as the detection alternative, which is actually more robust: it captures the command-line arguments of `schtasks.exe /create` with full fidelity.

**Splunk Detection Query:**

```spl
earliest=0 index=sysmon _raw="1"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| where like(lower(Image), "%schtasks%")
  AND like(lower(CommandLine), "%/create%")
| table _time, host, User, Image, CommandLine
| sort -_time
```

**Cleanup:**

```powershell
Invoke-AtomicTest T1053.005 -Cleanup
```

**Evidence:**

![T1053.005 Tasks Created](screenshots/T1053.005%20(Calculator%2C%20Event%20Viewer%20launched).png)
![T1053.005 Detection](screenshots/Splunk%20Sysmon%20Detection%20-%20T1053.005%20—%20Scheduled%20Task%20Persistence.png)


---

### T1021.002 — Remote Services: SMB/Windows Admin Shares

**Tactic:** Lateral Movement | **Technique:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

Windows admin shares (`C$`, `ADMIN$`, `IPC$`) are hidden network shares enabled by default on Windows. Authenticated users with Administrator privileges can use them to browse remote filesystems, copy files, or execute commands — making them a common lateral movement vector in enterprise environments.

**Execution:**

```powershell
Invoke-AtomicTest T1021.002
```

**Sub-test Results:**

| Test | Result | Notes |
|------|--------|-------|
| 1 — Net share access by hostname | ❌ Failed | "Network name cannot be found" — hostname `Target` not resolvable in lab |
| 2 — Map `\\Target\C$` as drive | ✅ Succeeded | Mapped as drive `G:` via PowerShell; Exit code 0 confirms admin share access |
| 3 — PsExec remote execution | ❌ Failed | PsExec not present on system |
| 4 — Write to admin share | ✅ Succeeded | Command output written to local admin share |

**Why Splunk did not detect it:**

Sub-test 2 mapped `\\Target\C$`, but `Target` resolved to localhost (loopback). When SMB traffic stays on the same machine, Windows does **not** generate EventCode 4624 LogonType=3 (network logon) — because there is no actual network hop. Similarly, Sysmon does not log EventID 3 for loopback connections. Nothing appeared in Splunk — not because the detection logic is wrong, but because the single-machine lab setup made it a loopback scenario.

> **In a real multi-host environment:** If the attacker and target are separate machines, EventCode 4624 LogonType=3 would fire on the target host, and Sysmon EventID 3 targeting port 445 would appear on the attacker. The detection query below is correct for that scenario.

**Detection Query (multi-host environment):**

```spl
earliest=0 index=wineventlog EventCode=4624
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<account>[^\r\n]+)"
| where LogonType="3"
| table _time, host, src_ip, account, LogonType
| sort -_time
```

**Evidence:**

![T1021.002 Output](screenshots/T1021.002.png)

---

### T1046 — Network Service Discovery

**Tactic:** Discovery | **Technique:** [T1046](https://attack.mitre.org/techniques/T1046/)

Port scanning is typically one of the first actions an attacker takes after gaining a foothold — identifying which services are running on target systems informs follow-on exploitation decisions.

**Execution (from Kali):**

```bash
# Enable SMB inbound on Windows first
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

# Port scan from Kali
nmap -sV -p 1-1000 192.168.56.130
```

**Result:** Port 445 (SMB/Microsoft-DS) identified as open. All other ports in range 1-1000 filtered.

> ⚠️ **Detection gap:** Nmap SYN scans are not captured by Windows Security event logs — there is no native Windows mechanism to log port scan attempts. Real detection requires a network-layer tool: Snort, Suricata, Zeek, or NetFlow analysis. This is a fundamental limitation of host-based SIEM monitoring and a gap that warrants supplementing Splunk with an NIDS/IDS in any real deployment.

**Evidence:**

![Nmap Scan](screenshots/T1110-nmap.png)

---

### T1110 — Brute Force

**Tactic:** Credential Access | **Technique:** [T1110](https://attack.mitre.org/techniques/T1110/)

Credential brute-forcing attempts to authenticate as a valid user by systematically trying passwords. Each failed authentication generates Windows EventCode 4625 (Failed Logon) on the target. When the lockout threshold is exceeded, EventCode 4740 (Account Lockout) fires.

**Prerequisites on Windows VM:**

```powershell
# 1. Open SMB through the firewall
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

# 2. Enable account lockout policy
net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30
```

**Execution (from Kali):**

```bash
# Confirm SMB is reachable
nmap -p 445 192.168.56.130

# Brute force loop — 15 failed attempts
for i in {1..15}; do
  smbclient //192.168.56.130/C$ -U administrator%wrongpass$i 2>/dev/null
  echo "attempt $i"
done
```

**Splunk Detection Query — Multiple Failed Logons:**

```spl
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Account Name:\t+(?<account>[^\n]+)"
| bucket _time span=5m
| stats count as failed_attempts, values(account) as targeted_accounts by _time, src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

**Splunk Detection Query — Account Lockout:**

```spl
earliest=0 index=wineventlog EventCode=4740
| table _time, host, _raw
```

**Detection logic:** The first query applies a sliding window (5-minute buckets) and flags any source IP that generates 5+ failed logon attempts within that window — a signature consistent with automated credential stuffing or brute-force tools. The threshold of 5 should be tuned against the environment's baseline; in most environments 5 failures in 5 minutes from a single IP is highly anomalous.

**Evidence:**

![T1110 Brute Force Activity](screenshots/T1110.png)
![T1110 Brute Force Nmap Pre-scan](screenshots/T1110-BruteForcing.png)
![T1110 Brute Force Detection](screenshots/Splunk%20Sysmon%20Detection%20-%20T1110%20-%20Brute%20Force%20Detection.png)

---

## Step 6 — SOC Dashboard

Built using **Splunk → Dashboards → Create New Dashboard → Classic Dashboard**. The dashboard provides a single-pane-of-glass view for analyst triage, combining failed authentication analytics with endpoint telemetry.

| Panel | Visualization | SPL Query |
|-------|--------------|-----------|
| Total Events Today | Single Value | `index=* earliest=-24h \| stats count` |
| Failed Logins Over Time | Line Chart | `earliest=0 index=wineventlog EventCode=4625 \| timechart span=1h count` |
| Top 10 Source IPs | Bar Chart | `earliest=0 index=wineventlog EventCode=4625 \| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)" \| stats count by src_ip \| sort -count \| head 10` |
| Top Users with Failed Logins | Statistics Table | `earliest=0 index=wineventlog EventCode=4625 \| rex field=_raw "Account Name:\t+(?<user>[^\n]+)" max_match=2 \| stats count by user \| sort -count` |
| Failed Logins by Source IP | Statistics Table | Same as above, grouped by `src_ip` |
| Sysmon Process Creation by Host | Statistics Table | `earliest=0 index=sysmon _raw="*<EventID>1</EventID>*" \| rex field=_raw "<Computer>(?<host>[^<]+)</Computer>" \| stats count by host \| sort -count` |
| Events by Index | Bar Chart | `earliest=0 index=* \| stats count by index \| sort -count` |

**Evidence:**

![SOC Dashboard](screenshots/SOC%20Dashboard.png)

---

## Detection Rules Summary

| Technique | MITRE ID | Detection Method | Key Log Source | Detected? |
|-----------|----------|-----------------|---------------|-----------|
| LSASS Credential Dump | T1003.001 | Sysmon EventID 1 — process image/cmdline contains `lsass` | `index=sysmon` | ✅ Detected (Defender blocked execution, attempt still logged) |
| PowerShell Abuse | T1059.001 | Sysmon EventID 1 — PowerShell with `-enc`, `-bypass`, `-nop`, `iex` | `index=sysmon` | ✅ Detected |
| Scheduled Task Persistence | T1053.005 | Sysmon EventID 1 — `schtasks.exe /create` | `index=sysmon` | ✅ Detected (Windows 4698 audit broken on Win11) |
| SMB Lateral Movement | T1021.002 | WinEventLog EventCode 4624 LogonType=3 | `index=wineventlog` | ❌ Not detected (loopback constraint in single-VM lab) |
| Network Service Discovery | T1046 | N/A — host-based SIEM gap | N/A | ❌ Requires NIDS/IPS |
| Brute Force | T1110 | WinEventLog EventCode 4625, 4740 | `index=wineventlog` | ✅ Detected |

---

## Known Issues & Limitations

| Issue | Root Cause | Resolution / Workaround |
|-------|-----------|------------------------|
| EventCode 4698 (Task Created) not logged | Windows 11 audit policy limitation — `Other Object Access Events` subcategory broken on this build | Used Sysmon EventID 1 on `schtasks.exe /create` as detection alternative |
| EventCode 4624 LogonType=3 not triggered for SMB | Loopback SMB traffic does not generate network logon events — no actual network hop occurs | Documented as lab constraint; detection logic is valid in real multi-host environments |
| Nmap port scans not visible in Splunk | Windows Security event logs do not capture port scan attempts (host-based SIEM gap) | Requires network-layer IDS/IPS (Snort, Suricata, Zeek); Kali terminal screenshot included as evidence |
| Sysmon forwarder silently dropped events | `SplunkForwarder` service account lacked read access on the Sysmon/Operational channel DACL | Changed service account to `LocalSystem` (`sc.exe config SplunkForwarder obj= "LocalSystem"`) |
| SMB brute force with Hydra failed | SMB protocol version incompatibility between Hydra and the Windows SMB implementation | Switched to `smbclient` loop from Kali |
| Kali lacks `/var/log/syslog` and `/var/log/auth.log` | Modern Kali uses `systemd-journald` — traditional syslog files not present | Monitored available log files: dpkg.log, apache2, vmware-network.log |

---

## Skills Demonstrated

**Detection Engineering**
- Writing Splunk SPL queries targeting specific MITRE ATT&CK techniques
- Understanding Windows event log data sources, event codes, and their limitations
- Using `rex` for field extraction from raw XML Sysmon event data
- Applying statistical detection logic (time-bucketing, threshold-based alerting)
- Distinguishing between host-based and network-based detection capabilities

**Endpoint Monitoring & Telemetry**
- Sysmon deployment and XML configuration with the SwiftOnSecurity ruleset
- Understanding key Sysmon EventIDs: 1 (Process Create), 3 (Network Connection), 11 (File Create)
- Diagnosing and resolving Windows Event Log channel access control issues (DACL)

**Adversary Emulation**
- Executing MITRE ATT&CK-mapped sub-tests with Atomic Red Team's `invoke-atomicredteam`
- Interpreting test output to understand which sub-tests succeeded or failed and why
- Cross-referencing attack execution results against SIEM telemetry to validate detection

**SIEM Administration**
- Splunk index design and data architecture for multi-source ingestion
- Universal Forwarder deployment on both Windows and Linux
- `inputs.conf` / `outputs.conf` configuration for forwarding Windows Event Logs and Sysmon
- Splunk Dashboard creation for SOC analyst triage

**Network Security Fundamentals**
- Understanding the detection gap between host-based and network-based monitoring
- Windows Firewall rule management for controlled lab traffic
- SMB/Windows admin share exploitation mechanics and lateral movement patterns
- Brute-force attack detection using authentication event analysis

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Atomic Red Team — Red Canary](https://github.com/redcanaryco/atomic-red-team)
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
- [Windows Security Audit Events Reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
- [Splunk Universal Forwarder Manual](https://docs.splunk.com/Documentation/Forwarder)
