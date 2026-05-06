# SOC LAB — ZERO TO HERO OPERATIONAL GUIDE
## Part 4: SOAR Automation, Playbooks & Full Checklist

---

## MODULE G — SHUFFLE SOAR + OLLAMA AI AUTOMATION

### G.1 — Verify the Full AI Pipeline is Running

```bash
# SSH into AI/SOAR VM
ssh admin@172.16.10.90

# Check Shuffle containers
cd /opt/shuffle
sudo docker-compose ps
# All should show: Up

# Test Ollama is running with llama3
curl http://localhost:11434/api/tags
# Expected: {"models":[{"name":"llama3:8b",...}]}

# Test Ollama generates a response
curl -X POST http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3:8b",
    "prompt": "You are a SOC analyst. Rate the severity 1-10: Kerberoasting attack detected on lab.local, RC4 encryption, service account svc_sql targeted.",
    "stream": false
  }'
```

### G.2 — Configure the Triage Workflow in Shuffle

```
URL: http://10.30.40.50:3001
Login: admin@shuffler.io / password

1. Go to Workflows → Create new workflow
   Name: "SOC Auto Triage v1"

2. Add Trigger: Webhook
   → Copy the webhook URL (format: http://172.16.10.90:3001/api/v1/hooks/XXXX)
   → Save this URL — needed for Kibana watcher

3. Add Action: "Repeat back to me" (for field extraction)
   Input: $exec (the full alert JSON from ELK)
   Extract fields:
     src_ip     = $exec.hits.hits.0._source.source.ip
     hostname   = $exec.hits.hits.0._source.host.name
     event_id   = $exec.hits.hits.0._source.winlog.event_id
     rule_name  = $exec.hits.hits.0._source.rule.name
     proc_hash  = $exec.hits.hits.0._source.process.hash.sha256

4. Add Action: HTTP (POST to Ollama)
   URL: http://172.16.10.90:11434/api/generate
   Method: POST
   Body:
   {
     "model": "llama3:8b",
     "prompt": "SOC analyst. Analyze alert: Rule=$rule_name, Host=$hostname, SrcIP=$src_ip, EventID=$event_id. Return JSON: {severity:1-10, summary:string, action:string, mitre:string}",
     "stream": false
   }

5. Add Action: HTTP (POST to OpenCTI — IOC check)
   URL: http://172.16.10.80:8080/graphql
   Method: POST
   Headers: Authorization: Bearer YOUR_OPENCTI_TOKEN
   Body:
   {
     "query": "{ stixCyberObservables(filters:[{key:\"value\",values:[\"$src_ip\"]}]) { edges { node { id entity_type } } } }"
   }

6. Add Action: HTTP (POST to Cortex — hash lookup)
   URL: http://172.16.10.20:9001/api/analyzer/VirusTotal_GetReport_3_0/run
   Method: POST
   Headers: Authorization: Bearer YOUR_CORTEX_API_KEY
   Body: {"data": "$proc_hash", "dataType": "hash", "tlp": 1}

7. Add Action: HTTP (POST to TheHive — create case)
   URL: http://172.16.10.20:9000/api/v1/case
   Method: POST
   Headers: Authorization: Bearer YOUR_THEHIVE_API_KEY
   Body:
   {
     "title": "$rule_name on $hostname",
     "description": "$ollama_summary",
     "severity": $ollama_severity,
     "tags": ["$ollama_mitre", "auto-triage", "shuffle"],
     "observables": [
       {"dataType": "ip", "data": "$src_ip"},
       {"dataType": "hash", "data": "$proc_hash"}
     ]
   }

8. Add Condition: IF ollama_severity >= 7
   → Add Action: HTTP (POST to Velociraptor — trigger hunt)
     URL: https://172.16.10.50:8000/api/v1/CreateHunt
     Method: POST
     Body:
     {
       "HuntDescription": "Auto-Hunt: $rule_name on $hostname",
       "StartRequest": {"flow_name": "Windows.KapeFiles.Targets"}
     }

9. Save and Enable the workflow
```

### G.3 — Connect Kibana Watcher → Shuffle

```bash
# On ELK VM (172.16.10.10)
# Replace WEBHOOK_ID with the ID from Shuffle webhook

curl -X PUT "http://172.16.10.10:9200/_watcher/watch/soc-alert-webhook" \
  -H 'Content-Type: application/json' \
  -u elastic:MOT_DE_PASSE \
  -d '{
    "trigger": {"schedule": {"interval": "1m"}},
    "input": {
      "search": {
        "request": {
          "indices": ["logs-*"],
          "body": {
            "query": {
              "bool": {
                "filter": [
                  {"range": {"@timestamp": {"gte": "now-1m"}}},
                  {"term": {"event.kind": "alert"}}
                ]
              }
            }
          }
        }
      }
    },
    "condition": {
      "compare": {"ctx.payload.hits.total.value": {"gt": 0}}
    },
    "actions": {
      "notify_shuffle": {
        "webhook": {
          "method": "POST",
          "url": "http://172.16.10.90:3001/api/v1/hooks/WEBHOOK_ID",
          "body": "{{ctx.payload}}",
          "headers": {"Content-Type": "application/json"}
        }
      }
    }
  }'

# Verify watcher was created
curl -u elastic:MOT_DE_PASSE \
  http://172.16.10.10:9200/_watcher/watch/soc-alert-webhook

# Test trigger manually
curl -X PUT "http://172.16.10.10:9200/_watcher/watch/soc-alert-webhook/_execute" \
  -u elastic:MOT_DE_PASSE
```

### G.4 — Test the Full AI Pipeline End-to-End

```bash
# 1. From Kali, run a quick Kerberoasting attack (triggers Event 4769)
GetUserSPNs.py lab.local/alice.dupont:Password123 -dc-ip 172.16.20.10 -request

# 2. Wait 1-2 minutes for:
#    ELK detects event 4769 → Watcher fires → Shuffle triggered → Ollama analyzes
#    → OpenCTI checked → Cortex runs VirusTotal → TheHive case created

# 3. Check Shuffle execution log:
#    http://10.30.40.50:3001 → Workflows → SOC Auto Triage → Executions

# 4. Check TheHive for auto-created case:
#    http://10.30.40.50:9000 → Cases → Most recent

# 5. Verify Ollama response in Shuffle execution:
#    Should contain: severity, summary, action, mitre technique
```

---

## MODULE H — INCIDENT RESPONSE PLAYBOOKS

### PLAYBOOK 1 — KERBEROASTING RESPONSE

**Trigger:** Event ID 4769 with TicketEncryptionType=0x17, OR Suricata SID 1000003

**Step 1 — Triage (0-5 min)**
```
Kibana query:
  event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17"

Note:
- Which service account was targeted? (ServiceName field)
- Which user requested it? (SubjectUserName field)
- Source IP of the request?
- Timestamp?
```

**Step 2 — Confirm Attack (5-10 min)**
```bash
# On ELK VM — verify the account has an SPN
# SSH into DC01 first:
ssh Administrator@172.16.20.10

# Check SPN on DC01 (PowerShell)
Get-ADUser -Identity svc_sql -Properties ServicePrincipalNames |
  Select ServicePrincipalNames

# Check for RC4 downgrade in domain policy
Get-ADObject -SearchBase "CN=Policies,CN=System,DC=lab,DC=local" -Filter * |
  Get-ADObject -Properties msDS-SupportedEncryptionTypes
```

**Step 3 — Containment**
```powershell
# On DC01 — Disable the targeted service account immediately
Disable-ADAccount -Identity svc_sql

# Reset the password with a strong one (30+ chars)
Set-ADAccountPassword -Identity svc_sql `
  -NewPassword (ConvertTo-SecureString "Xk9#mP2$vL8@qR5&nY7!jT4^wE6*uA3" -AsPlainText -Force) `
  -Reset

# Force AES encryption for service account (prevent RC4 downgrade)
Set-ADUser -Identity svc_sql -KerberosEncryptionType AES128,AES256

# In pfSense — block Kali IP if this is a real scenario
# Firewall > Rules > ATTACKER > Add block rule for 172.16.99.10
```

**Step 4 — Evidence Collection**
```bash
# Velociraptor — hunt for cracking tools on attacker's machine
# (if attacker is inside the network)

# Export Kibana logs as evidence
# Discover → share → Generate CSV

# On DC01 — export security event log
wevtutil epl Security C:\Evidence\Security_$(Get-Date -f yyyyMMdd).evtx
```

**Step 5 — TheHive Case Update**
```
Status: InProgress → Resolved
Close notes: "Kerberoasting confirmed. svc_sql account disabled and
password reset. AES encryption enforced. Attack originated from
172.16.99.10 (Kali lab attacker). No evidence of successful crack
or lateral movement."
TruePositive: Yes
MITRE: T1558.003
```

---

### PLAYBOOK 2 — PASS-THE-HASH RESPONSE

**Trigger:** Event ID 4624 LogonType=3, NTLM auth, source IP unexpected

**Step 1 — Triage**
```
Kibana:
  event.code: "4624"
    AND winlog.event_data.LogonType: "3"
    AND winlog.event_data.AuthenticationPackageName: "NTLM"

Check:
- Which account was used? (bob.admin = DA — CRITICAL)
- From which IP?
- What systems were accessed?
- What commands were run after? (correlate Sysmon 1)
```

**Step 2 — Confirm via Velociraptor**
```
Velociraptor → WIN-TARGET-2 → Shell:

# Check who is currently logged in
query users
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10 | Format-List

# Check for active sessions
net session
```

**Step 3 — Containment**
```powershell
# On DC01 — Disable compromised account
Disable-ADAccount -Identity bob.admin

# Reset NTLM hash by resetting password
Set-ADAccountPassword -Identity bob.admin `
  -NewPassword (ConvertTo-SecureString "N3wStr0ng#P@ss2026!" -AsPlainText -Force) `
  -Reset

# Revoke all Kerberos tickets (forces re-authentication)
# Run on affected workstation:
klist purge

# On DC01 — Reset krbtgt password (twice!) if DCSync was performed
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "Kr8TGT#2026$Reset!" -AsPlainText -Force) -Reset
# Wait 10 min, reset AGAIN to invalidate all Golden Tickets
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "Kr8TGT#2026$Reset2!" -AsPlainText -Force) -Reset
```

**Step 4 — Eradication**
```
Velociraptor hunt on WIN-TARGET-2:
- Find Mimikatz or any credential harvesting tool
- Check registry for persistence
- Check scheduled tasks
- Check startup folders

VQL:
SELECT FullPath, Size, Mtime
FROM glob(globs=["C:\\Windows\\Temp\\**", "C:\\Users\\**\\AppData\\Local\\Temp\\**"])
WHERE FullPath =~ "\.exe$" OR FullPath =~ "\.dll$"
```

---

### PLAYBOOK 3 — BRUTE FORCE RESPONSE

**Trigger:** 10+ Event ID 4625 from same source IP in 5 min, OR Suricata SID 1000002

**Step 1 — Triage**
```
Kibana:
  event.code: "4625"
  | stats count by source.ip, user.name
  | sort count desc

Check:
- Is the source IP internal or external?
- Which usernames targeted?
- Any successful logon (4624) after the failures?
```

**Step 2 — Block in pfSense**
```
pfSense WebUI → https://10.30.40.50
Firewall → Rules → ATTACKER (VLAN 99)
Add rule: Block TCP from 172.16.99.10 to 172.16.20.30 port 22,445,3389

Or via pfSense shell (SSH to pfSense):
pfctl -t bruteforce -T add 172.16.99.10
```

**Step 3 — Lockout Review**
```powershell
# On DC01 — Check locked accounts
Search-ADAccount -LockedOut | Select Name, SamAccountName, LockedOut

# Unlock if needed (after confirming it's a lab test)
Unlock-ADAccount -Identity alice.dupont

# Check fine-grained password policy
Get-ADFineGrainedPasswordPolicy -Filter *
```

---

### PLAYBOOK 4 — LINUX INTRUSION RESPONSE

**Trigger:** Suricata SSH alert, OR Linux auditd failure followed by success from same IP

**Step 1 — Triage**
```bash
# SSH into Linux Target for investigation
ssh admin@172.16.30.10  # (using admin account, not labuser)

# Check who is logged in RIGHT NOW
who
w
last -20

# Check bash history of compromised user
sudo cat /home/labuser/.bash_history

# Check /tmp for dropped files
ls -la /tmp/
find /tmp -type f -newer /tmp -ls
```

**Step 2 — Isolate**
```bash
# Block Kali IP in iptables on Linux Target
sudo iptables -A INPUT -s 172.16.99.10 -j DROP
sudo iptables -A OUTPUT -d 172.16.99.10 -j DROP

# Change labuser password immediately
sudo passwd labuser

# Kill attacker's active SSH session
# Find session PID
sudo ss -tp | grep 172.16.99.10
# Kill it
sudo kill -9 <PID>
```

**Step 3 — Evidence Collection**
```bash
# Copy all logs before any cleanup
sudo cp /var/log/auth.log /tmp/evidence-auth.log
sudo cp /var/log/syslog /tmp/evidence-syslog.log
sudo journalctl > /tmp/evidence-journal.log

# Capture network state
sudo netstat -tupln > /tmp/evidence-netstat.txt
sudo ss -tupln >> /tmp/evidence-netstat.txt

# List all processes
ps auxf > /tmp/evidence-processes.txt

# SCP evidence to SIFT VM
scp /tmp/evidence-* analyst@172.16.10.70:/mnt/cases/linux/
```

---

## MODULE I — COMPLETE DAILY/WEEKLY CHECKLIST

### Daily SOC Checklist
```
[ ] Login to Kibana → check open alerts (Security → Alerts)
[ ] Review TheHive → any new auto-cases from Shuffle?
[ ] Check Velociraptor → all 3 agents online?
[ ] Check Suricata → any high-severity alerts in last 24h?
[ ] Verify Logstash → logs still flowing (check timestamps in Discover)
[ ] Review Shuffle → last workflow executions successful?
[ ] Check Ollama → AI triage working (test a manual query)
```

### Weekly Threat Hunting Checklist
```
[ ] Run VQL Hunt: Search for mimikatz/offensive tools on all endpoints
[ ] Run VQL Hunt: Find new scheduled tasks created this week
[ ] Run VQL Hunt: Find new registry Run keys
[ ] Run VQL Hunt: Network connections to unusual IPs
[ ] Review Sigma rules → any new rules to import?
[ ] Update Suricata rules: sudo suricata-update
[ ] Check OpenCTI for new threat intelligence feeds
[ ] Review ATT&CK Navigator → update coverage map
[ ] Run a test attack scenario → verify detection pipeline works end-to-end
[ ] Document any new findings in TheHive
```

---

## MODULE J — VERIFICATION COMMANDS (FINAL HEALTH CHECK)

```bash
# === ELK Stack ===
curl -u elastic:PASS http://172.16.10.10:9200/_cluster/health?pretty
curl -u elastic:PASS http://172.16.10.10:9200/_cat/indices?v

# === Suricata ===
sudo systemctl status suricata
sudo tail -5 /var/log/suricata/eve.json | jq '.event_type'

# === Velociraptor ===
curl -k https://172.16.10.50:8000/ | head -5

# === Shuffle + Ollama ===
curl http://172.16.10.90:11434/api/tags
curl http://172.16.10.90:3001/api/v1/health

# === TheHive ===
curl http://172.16.10.20:9000/api/status

# === OpenCTI ===
curl http://172.16.10.80:8080/health

# === Test log flow ===
# On WIN-TARGET-1 (PowerShell) — generate an event
Add-EventLog -LogName Application -Source "Test" -Message "SOC Test Event" 2>/dev/null
Write-EventLog -LogName Application -Source "Test" -EventId 999 -Message "Lab health check"
# Then check Kibana for this event within 2 minutes
```

---

## QUICK IP / PORT REFERENCE

| VM | IP | Key Ports |
|---|---|---|
| ELK Stack | 172.16.10.10 | 9200 (ES), 5601 (Kibana), 5044 (Logstash) |
| TheHive+Cortex | 172.16.10.20 | 9000 (TheHive), 9001 (Cortex) |
| Suricata | 172.16.10.40 | — (passive listener) |
| Velociraptor | 172.16.10.50 | 8000 (UI+agents) |
| SIFT Forensics | 172.16.10.70 | 22 (SSH) |
| OpenCTI | 172.16.10.80 | 8080 (UI), 4242 (ATT&CK Nav) |
| AI/SOAR | 172.16.10.90 | 3001 (Shuffle), 11434 (Ollama) |
| DC01 | 172.16.20.10 | 389 (LDAP), 88 (Kerberos), 445 (SMB) |
| WIN-TARGET-1 | 172.16.20.30 | 3389 (RDP), 445 (SMB), 5985 (WinRM) |
| WIN-TARGET-2 | 172.16.20.31 | 3389 (RDP), 445 (SMB), 5985 (WinRM) |
| Linux Target | 172.16.30.10 | 22 (SSH), 80 (HTTP), 21 (FTP) |
| Kali Linux | 172.16.99.10 | attacker machine |

---

*End of Guide — All 4 parts complete.*
*Files: SOC_Lab_Complete_Guide_Part1.md through Part4.md*
