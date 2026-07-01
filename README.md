# SOC Home Lab

Built this to get hands-on with blue team tools before starting work. Splunk as the SIEM, Sysmon for endpoint logs, and Atomic Red Team to simulate attacks.

**Stack:** Splunk Enterprise · Sysmon · Atomic Red Team · Hydra · Nmap · VirtualBox

| VM | OS | IP | Role |
|---|---|---|---|
| Windows | Windows 11 | 192.168.56.130 | Splunk + target |
| Kali | Kali Linux | 192.168.56.129 | Attacker |

---

## Attacks + Detections

| Technique | What I did | Splunk result |
|---|---|---|
| T1003.001 — LSASS Dump | Ran Atomic Red Team test, Defender blocked it | No EventID 10 — Defender killed it too fast. PowerShell CommandLine still shows the attempt |
| T1059.001 — PowerShell | Atomic Red Team tests with encoded commands | 3 hits — CommandLine shows -EncodedCommandParamVariation flags |
| T1053.005 — Scheduled Task | Atomic Red Team created persistence tasks | 7 hits — schtasks.exe /create with task names like AtomicTask, EventViewerBypass |
| T1021.002 — SMB | Mapped admin share via PowerShell | Share mapped successfully, no Splunk hit (loopback gap — see below) |
| T1046 — Port Scan | Nmap from Kali | Port 445 open, rest filtered |
| T1110 — Brute Force | smbclient loop 15 attempts from Kali | 10 EventCode 4625s detected, account locked out at attempt 11 |

Detection queries: [detection-rules/splunk_queries.md](detection-rules/splunk_queries.md)
Setup notes: [docs/setup-notes.md](docs/setup-notes.md)

---

## Gaps / things that didn't work how I expected

- **T1003.001:** Defender blocked the LSASS dump before Sysmon could log EventID 10. The attempt still shows up in PowerShell process logs.
- **T1021.002:** SMB test was loopback so Windows didn't generate EventCode 4624 LogonType=3. Would fire in a real multi-machine setup.
- **T1046:** Nmap scans don't show up in Windows event logs reliably. You'd need a network IDS for that.
- **Kali logs:** Kali uses journald so there's no auth.log. Only forwarding dpkg.log.
- **EventCode 4698:** Scheduled task creation event didn't fire on Windows 11 even after enabling audit policy. Used Sysmon process logs instead.
