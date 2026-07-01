# SOC Home Lab — Splunk SIEM + MITRE ATT&CK Detection

Home lab built to practice SOC analyst skills. Splunk as the SIEM, Sysmon for endpoint telemetry, Atomic Red Team for attack simulation.

---

## Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| Windows VM | Windows 11 | 192.168.56.130 | Splunk Enterprise + target |
| Kali VM | Kali Linux | 192.168.56.129 | Attacker |

Both VMs on VirtualBox with a host-only network adapter.

---

## Setup Overview

1. **Splunk Enterprise** — installed on Windows VM, created indexes (wineventlog, sysmon, syslog), receiving on port 9997
2. **Sysmon** — installed with SwiftOnSecurity config, forwarded to Splunk via Universal Forwarder
3. **Universal Forwarder (Windows)** — forwarding Security logs + Sysmon to localhost:9997
4. **Universal Forwarder (Kali)** — transferred .deb via Python HTTP server, forwarding dpkg.log
5. **Atomic Red Team** — installed on Windows VM, ran attack simulations
6. **Kali attacks** — Nmap recon + SMB brute force with smbclient

Full setup commands in [`docs/setup-notes.md`](docs/setup-notes.md)

---

## Attack Simulations

### T1003.001 — LSASS Memory Dump

**Execution:**
```powershell
Invoke-AtomicTest T1003.001
```

**Result:** All sub-tests blocked by Defender. The attempt still logged in Sysmon EventID 1 (process creation) and visible via PowerShell CommandLine field.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*lsass*"
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| where NOT like(Image, "%Photos%")
  AND NOT like(Image, "%SnippingTool%")
  AND NOT like(Image, "%PickerHost%")
| table _time, host, Image, CommandLine
| sort -_time
```

---

### T1059.001 — PowerShell Execution

**Execution:**
```powershell
Invoke-AtomicTest T1059.001
```

**Result:** 3 hits in Splunk. CommandLine shows `-EncodedCommandParamVariation` and `-Execute` flags from Atomic Red Team sub-tests.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*<EventID>1</EventID>*"
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

---

### T1053.005 — Scheduled Task Persistence

**Execution:**
```powershell
Invoke-AtomicTest T1053.005
```

**Result:** 7 hits in Splunk. Tasks created: `ATOMIC-T1053.005`, `EventViewerBypass`, `CompMgmtBypass`, `Atomic task`, `spawn`, `T1053_005_OnStartup`, `T1053_005_OnLogon`.

Note: EventCode 4698 (task creation audit event) did not fire on Windows 11 even with audit policy enabled. Used Sysmon process monitoring instead.

**Detection Query:**
```spl
earliest=0 index=sysmon _raw="*<EventID>1</EventID>*"
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

---

### T1021.002 — SMB Admin Share Access

**Execution:**
```powershell
Invoke-AtomicTest T1021.002
```

**Sub-test results:**

| Test | Result | Notes |
|---|---|---|
| 1 — Net share by hostname | ❌ | Hostname `Target` not resolvable |
| 2 — Map `\\Target\C$` as drive | ✅ | Mapped as drive G:, Exit code 0 |
| 3 — PsExec execution | ❌ | PsExec not present |
| 4 — Write to admin share | ✅ | Exit code 0 |

**Detection gap:** Test 2 mapped `\\Target\C$` which resolved to localhost. Loopback SMB doesn't generate EventCode 4624 LogonType=3 or Sysmon EventID 3. Would fire in a real multi-host setup.

**Detection Query (multi-host):**
```spl
earliest=0 index=wineventlog EventCode=4624
| rex field=_raw "Logon Type:\s+(?<LogonType>\d+)"
| rex field=_raw "Source Network Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "Account Name:\s+(?<account>[^\r\n]+)"
| where LogonType="3"
| table _time, host, src_ip, account
| sort -_time
```

---

### T1046 — Network Service Discovery

**Execution (from Kali):**
```bash
nmap -sV -p 1-1000 192.168.56.130
```

**Result:** Port 445 (SMB) open, rest filtered.

**Detection gap:** Nmap scans aren't captured by Windows event logs. Requires network-level IDS/IPS.

---

### T1110 — Brute Force

**Prerequisites on Windows VM:**
```powershell
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
net accounts /lockoutthreshold:10 /lockoutduration:30 /lockoutwindow:30
```

**Execution (from Kali):**
```bash
for i in {1..15}; do smbclient //192.168.56.130/C$ -U administrator%wrongpass$i 2>/dev/null; echo "attempt $i"; done
```

**Result:** Attempts 1-10 returned `NT_STATUS_LOGON_FAILURE`, attempts 11-15 returned `NT_STATUS_ACCOUNT_LOCKED_OUT`. 10 EventCode 4625s detected in Splunk.

**Detection Query:**
```spl
earliest=0 index=wineventlog EventCode=4625
| rex field=_raw "Source Network Address:\t+(?<src_ip>[^\n]+)"
| rex field=_raw "Account Name:\t+(?<account>[^\n]+)" max_match=2
| bucket _time span=5m
| stats count as failed_attempts, values(account) as targeted_accounts by _time, src_ip
| where failed_attempts >= 5
| sort -failed_attempts
```

---

## Detection Summary

| Technique | Log Source | Detected? |
|---|---|---|
| T1003.001 — LSASS | sysmon (EventID 1) | ✅ Attempt logged despite Defender block |
| T1059.001 — PowerShell | sysmon (EventID 1) | ✅ 3 hits |
| T1053.005 — Scheduled Task | sysmon (EventID 1) | ✅ 7 hits |
| T1021.002 — SMB | wineventlog (4624 LogonType=3) | ❌ Loopback gap |
| T1046 — Nmap | N/A | ❌ Requires network IDS |
| T1110 — Brute Force | wineventlog (4625, 4740) | ✅ 10 hits, account locked |

---

## Known Issues

- **EventCode 4698** didn't fire on Windows 11 for scheduled task creation — used Sysmon instead
- **T1021.002** loopback SMB doesn't generate network logon events
- **T1046** host-based SIEM can't detect port scans
- **Sysmon forwarder** needed LocalSystem account to read the Sysmon/Operational channel
- **Kali** uses journald — no auth.log, forwarding dpkg.log instead
- **Hydra SMB** doesn't work against Windows 11 — used smbclient loop instead

---

## Tools Used

- [Splunk Enterprise](https://www.splunk.com/)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) + [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam)
- [Nmap](https://nmap.org/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [VirtualBox](https://www.virtualbox.org/)
