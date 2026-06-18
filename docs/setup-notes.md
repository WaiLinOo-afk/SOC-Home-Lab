# Setup Notes

Step-by-step notes from building the lab. Includes gotchas and fixes.

---

## Step 1 — Splunk Enterprise

Downloaded Windows .msi from splunk.com, installed on Windows VM (192.168.56.128) with default settings.

After first login at http://localhost:8000:

**Create indexes** (Settings > Indexes > New Index):
- wineventlog
- sysmon
- syslog

**Set receiving port** (Settings > Forwarding and Receiving > Configure Receiving > New Receiving Port):
- Port: 9997

---

## Step 2 — Sysmon

Downloaded from Microsoft Sysinternals. Used SwiftOnSecurity config.

Install (PowerShell as Administrator):
```powershell
cd C:\...\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify:
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Step 3 — Universal Forwarder (Windows)

Downloaded 64-bit .msi from splunk.com. During install, pointed receiving indexer to 127.0.0.1:9997.

Config files go in C:\Program Files\SplunkUniversalForwarder\etc\system\local\ — see splunk-configs/

### Fix: Sysmon permission issue

Forwarder can't read Sysmon/Operational log channel by default (only LocalSystem/Administrators allowed):

```powershell
sc.exe config SplunkForwarder obj= "LocalSystem"
Restart-Service SplunkForwarder
```

Verify in Splunk:
```
index=wineventlog | head 10
index=sysmon | head 10
```

---

## Step 4 — Universal Forwarder (Kali)

splunk.com was blocked on Kali's network — transferred file via Python HTTP server:

```powershell
# On Windows VM
cd C:\...\Downloads
python -m http.server 8080
```

```bash
# On Kali
wget http://192.168.56.128:8080/splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
sudo dpkg -i splunkforwarder-10.4.0-f798d4d49089-linux-amd64.deb
```

Config files go in /opt/splunkforwarder/etc/system/local/ — see splunk-configs/

### Fix: Windows firewall blocking port 9997

```powershell
New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

Verify in Splunk: index=syslog should return events with host=kali

---

## Step 5 — Atomic Red Team

```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force
Install-Module -Name invoke-atomicredteam -Force
Import-Module invoke-atomicredteam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Windows Defender will flag things during install — expected. Add exclusion:
```powershell
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"
```

Run and save output (the *>&1 redirects all streams — without it the file will be empty):
```powershell
Invoke-AtomicTest T1003.001 *>&1 | Out-File -FilePath "T1003_001_output.txt"
```

---

## Step 6 — Kali Attacks

Enable SMB (for nmap):
```powershell
New-NetFirewallRule -DisplayName "Allow SMB Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
```

Enable RDP (for Hydra brute force):
```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
Start-Service TermService
```

Nmap scan from Kali:
```bash
nmap -sV -p 1-1000 192.168.56.128
```

Hydra brute force from Kali:
```bash
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.56.128 rdp -t 4 -V
```

---

## Step 7 — SOC Dashboard

Splunk > Dashboards > Create New Dashboard > Classic Dashboard
Name: SOC Dashboard

Add a panel for each detection rule. Set time range to All Time on each panel.
