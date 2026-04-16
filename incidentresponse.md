Incident Response 





```bash
# Map every live host on your subnet immediately
nmap -sn 10.0.0.0/24            # ping sweep
nmap -sV -O -p- 10.0.0.0/24    # full port + service scan (run in bg)
```
Record every IP, hostname, open port, and running service. This is your **baseline**. Anything new that appears later is suspicious.

### 0.2 Run the DSU Scripts First
```bash
# Deploy nftables firewall rules
sudo bash tables.sh

# Audit misconfigurations in service configs
sudo bash fruit.sh

# Check for backdoors & network exposure
sudo bash detective.sh

# Backup critical files before the chaos starts
sudo bash backup.sh
```

### 0.3 Snapshot User Accounts & Sudoers
```bash
# Save current user list
cat /etc/passwd > /tmp/baseline_passwd.txt
cat /etc/shadow > /tmp/baseline_shadow.txt
cat /etc/sudoers > /tmp/baseline_sudoers.txt
sudo cat /etc/sudoers.d/* >> /tmp/baseline_sudoers.txt
getent group sudo >> /tmp/baseline_groups.txt
```

### 0.4 Snapshot Running Processes & Network State
```bash
ps auxf > /tmp/baseline_ps.txt
ss -tulnp > /tmp/baseline_ports.txt
netstat -anp > /tmp/baseline_netstat.txt
ip route > /tmp/baseline_routes.txt
```

### 0.5 Check for Keyloggers & Suspicious Kernel Modules RIGHT NOW
```bash
# List loaded kernel modules — look for anything odd
lsmod | grep -v "^Module"

# Check for LD_PRELOAD hooks (common userspace keylogger method)
cat /etc/ld.so.preload          # should be empty or only legit entries
env | grep LD_PRELOAD

# Check for input device listeners
lsof /dev/input/*               # any process reading raw keyboard input?
ls -la /dev/input/

# Check /proc for hidden processes (rootkit indicator)
ps aux > /tmp/ps_check.txt
ls /proc | grep -E '^[0-9]+$' | while read pid; do
  if ! grep -q " $pid " /tmp/ps_check.txt 2>/dev/null; then
    echo "HIDDEN PID: $pid  $(cat /proc/$pid/cmdline 2>/dev/null)"
  fi
done
```

---

## Phase 1 — Detection (Ongoing Throughout the Comp)

### 1.1 Watch for New/Modified Files
```bash
# Files modified in the last 10 minutes — run repeatedly
find / -mmin -10 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null

# Watch for new SUID/SGID binaries (privilege escalation)
find / -perm /4000 -o -perm /2000 2>/dev/null | sort > /tmp/suid_now.txt
diff /tmp/suid_baseline.txt /tmp/suid_now.txt   # create baseline first!
```

### 1.2 Monitor Active Network Connections
```bash
# Real-time connection monitor — run in a dedicated terminal
watch -n 2 'ss -tulnp; echo "---ESTABLISHED---"; ss -tnp state established'

# Capture traffic on your interface for later analysis
sudo tcpdump -i eth0 -w /tmp/capture_$(date +%H%M).pcap &

# Look for outbound connections to weird IPs
ss -tnp state established | grep -v "127.0.0.1\|::1"
```

### 1.3 Monitor Logins & Auth Attempts
```bash
# Who is currently logged in
who
w

# Recent login history
last | head -40
lastb | head -20    # failed logins

# Tail auth log live
sudo tail -f /var/log/auth.log       # Debian/Ubuntu
sudo tail -f /var/log/secure         # RHEL/CentOS
```

### 1.4 Watch Cron & Systemd for Persistence
```bash
# All crontabs
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -u $user -l 2>/dev/null | grep -v "^#" && echo "  ^ $user"
done
ls -la /etc/cron* /var/spool/cron/

# Systemd timers and suspicious units
systemctl list-timers --all
systemctl list-units --type=service --state=running
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /tmp/baseline_passwd.txt 2>/dev/null
```

### 1.5 Process Monitoring with pspy (included in repo)
```bash
# pspy64 catches processes run by any user without needing root
chmod +x open3/pspy64
./open3/pspy64 -pf -i 1000    # poll every 1 second, show file events
# Look for: cron jobs, scripts run by root, unusual parent-child combos
```

### 1.6 Lynis Security Audit (included in repo)
```bash
cd open3/lynis
sudo ./lynis audit system      # full audit, generates a report
# Focus on: warnings, suggestions, authentication hardening
```

---

## Phase 2 — Containment

### 2.1 If You Spot a Malicious Process
```bash
# Identify what it's doing before killing it
ls -la /proc/<PID>/exe         # what binary?
cat /proc/<PID>/cmdline        # full command line
lsof -p <PID>                  # open files and sockets

# Kill it
kill -9 <PID>

# If it respawns, find the parent
ps -p <PID> -o ppid=           # get parent PID, investigate that too
```

### 2.2 If You Find a Backdoor User
```bash
# Lock the account immediately
sudo usermod -L <username>

# Kill all their active sessions
sudo pkill -u <username>

# Remove from sudoers if present
sudo deluser <username> sudo    # Debian
sudo gpasswd -d <username> wheel  # RHEL

# Remove the account entirely (careful — only if clearly malicious)
sudo userdel -r <username>
```

### 2.3 If You Find Malicious SSH Keys
```bash
# Check all authorized_keys files
find /home /root -name "authorized_keys" -exec cat {} \; -print

# Compare against your known good baseline
# Remove any unknown keys immediately
nano /home/<user>/.ssh/authorized_keys
```

### 2.4 Network-Level Containment (nftables)
```bash
# Block a specific IP immediately
sudo nft add rule inet filter input ip saddr <ATTACKER_IP> drop
sudo nft add rule inet filter output ip daddr <ATTACKER_IP> drop

# Block a suspicious port
sudo nft add rule inet filter input tcp dport <PORT> drop

# See current ruleset
sudo nft list ruleset
```

### 2.5 If You Suspect a Keylogger
```bash
# Kill any process reading /dev/input
lsof /dev/input/* | awk 'NR>1 {print $2}' | sort -u | xargs kill -9

# Check for suspicious LD_PRELOAD library (hook-based keylogger)
cat /etc/ld.so.preload
# If something is there that shouldn't be — REMOVE IT and run ldconfig

# Check for kernel-level input capture
dmesg | grep -i "input\|keyboard"
lsmod | grep -i "input\|kbd\|key"
```

---

## Phase 3 — Eradication

### 3.1 Remove Persistence Mechanisms
```bash
# Cron persistence
crontab -r                        # your own
sudo crontab -u <baduser> -r      # another user's

# Systemd persistence
sudo systemctl disable <bad_service>
sudo systemctl stop <bad_service>
sudo rm /etc/systemd/system/<bad_service>.service
sudo systemctl daemon-reload

# rc.local / init persistence
cat /etc/rc.local
# Remove any suspicious entries

# Bashrc persistence (common!)
grep -r "curl\|wget\|nc\|bash -i\|/tmp/" /home/*/.bashrc /root/.bashrc ~/.profile /etc/profile /etc/profile.d/
```

### 3.2 Change All Credentials
```bash
# Change passwords for ALL users immediately at start
for user in $(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd); do
  echo "Changing password for: $user"
  passwd $user
done
sudo passwd root

# Rotate SSH host keys if compromised
sudo rm /etc/ssh/ssh_host_*
sudo dpkg-reconfigure openssh-server   # Debian
sudo ssh-keygen -A && sudo systemctl restart sshd  # generic
```

### 3.3 Harden SSH (Critical)
```bash
sudo nano /etc/ssh/sshd_config
# Set these:
#   PermitRootLogin no
#   PasswordAuthentication no        (if using keys) or set to yes with strong passwords
#   MaxAuthTries 3
#   AllowUsers <your_team_users_only>
#   Protocol 2

sudo systemctl restart sshd
```

---

## Phase 4 — Recovery

### 4.1 Restore from Backup if Needed
```bash
# Using restic (included in repo open4/)
./open4/restic restore latest --target /
# Or use your backup.sh snapshots
```

### 4.2 Verify Services Are Still Running (Scoring)
```bash
# Check scored services are up — don't lose points while cleaning!
systemctl status apache2 nginx mysql postgresql ssh vsftpd smbd  # whatever you're running
curl -s http://localhost | head -5    # web service responding?
```

### 4.3 File Integrity Check
```bash
# Check for modified binaries (if you have debsums)
sudo debsums -c 2>/dev/null | head -30    # lists modified dpkg files

# Check common binary integrity manually
md5sum /usr/bin/ssh /usr/sbin/sshd /bin/bash /usr/bin/sudo > /tmp/binary_hashes_now.txt
# Compare against baseline if you made one
```

---

## Splunk / Log Analysis Guide

### Option A: Splunk Free (Quickstart on Your IR Box)

Splunk Free processes up to 500MB/day — plenty for a CTF.

```bash
# If Splunk is available on the comp network or you can install it:
wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.x/linux/splunk-9.x-Linux-x86_64.tgz'
tar xvzf splunk.tgz -C /opt
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt \
  --seed-passwd YourPassword123!
```

**Forward logs to Splunk:**
```bash
# Edit inputs.conf to ingest key logs
cat > /opt/splunk/etc/system/local/inputs.conf << 'EOF'
[monitor:///var/log/auth.log]
index = main
sourcetype = linux_secure

[monitor:///var/log/syslog]
index = main
sourcetype = syslog

[monitor:///var/log/apache2/access.log]
index = main
sourcetype = access_combined

[monitor:///var/log/apache2/error.log]
index = main
sourcetype = apache_error
EOF

/opt/splunk/bin/splunk restart
# Access at http://localhost:8000
```

### Option B: Splunk Universal Forwarder (Forward to Central Splunk)

If your team has a central Splunk indexer:
```bash
# On each machine you want to monitor:
/opt/splunkforwarder/bin/splunk add forward-server <SPLUNK_INDEXER_IP>:9997
/opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
/opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
/opt/splunkforwarder/bin/splunk start
```

### Option C: No Splunk? Use These grep One-Liners Instead

```bash
# Failed SSH logins (brute force)
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Successful logins
grep "Accepted" /var/log/auth.log

# New user created
grep "useradd\|adduser" /var/log/auth.log

# Sudo usage
grep "sudo" /var/log/auth.log | grep -v "session"

# Connections to your box right now
ss -tnp state established

# Processes spawned by apache/www-data (web shell indicator)
ps aux | grep www-data
```

### Key Splunk SPL Queries for Competition

Once Splunk is running, use these searches:

```spl
-- Failed SSH logins
index=main sourcetype=linux_secure "Failed password"
| stats count by src_ip
| sort -count

-- Successful logins from external IPs
index=main sourcetype=linux_secure "Accepted password" OR "Accepted publickey"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| where src_ip != "127.0.0.1"
| table _time, user, src_ip, method

-- New cron jobs created
index=main "crontab" OR "CRON" "CMD"
| table _time, host, _raw

-- Suspicious outbound connections (from syslog/firewall)
index=main sourcetype=syslog dest_port!=80 dest_port!=443 dest_port!=22
| stats count by src_ip, dest_ip, dest_port

-- Sudo escalation events
index=main sourcetype=linux_secure "sudo:"
| table _time, host, _raw
```

---

## Quick Reference — Indicators of Compromise (IoCs)

| What You See | What It Means | Action |
|---|---|---|
| Unknown process reading `/dev/input/*` | Keylogger | Kill PID, check lsmod |
| Entry in `/etc/ld.so.preload` | Library injection / hook | Remove file, run ldconfig |
| Unknown `.service` file in systemd | Persistence | Disable, stop, delete |
| SSH authorized_keys with unknown key | Backdoor | Remove key, rotate passwords |
| Cron job running from `/tmp` | Persistence | Remove cron, delete file |
| New UID 0 (root) account | Privilege backdoor | Lock and remove immediately |
| Outbound connection to non-LAN IP | Exfil / C2 | Block IP, kill process |
| `nc`, `bash -i`, `/dev/tcp` in processes | Reverse shell | Kill immediately |
| Modified system binary | Trojanized binary | Restore from package |
| Unknown SUID binary | Privesc tool | Remove SUID bit or delete |

---

## Team Coordination Tips

- **Assign roles at start:** 1 person owns firewall, 1 person owns monitoring, rest handle services
- **Use a shared doc or whiteboard** to log every IoC found and action taken
- **Don't kill services** that are being scored — check the scoring rules first
- **Re-run `detective.sh` and `fruit.sh` every 15–20 minutes** — the red team will try to re-establish access
- **pspy64 in a dedicated terminal** watching for new processes the whole comp
- **Change ALL passwords in the first 2 minutes** — this is your single highest-value action

---

*Playbook built for NCAE Cyber Games using DSU-DefSec/cyber repo tools*
