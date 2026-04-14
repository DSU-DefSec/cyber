#!/bin/bash
# ============================================================
#   detective.sh - Backdoor & Compromise Detection Script
#   For use on Ubuntu / Rocky Linux (Debian & RHEL families)
#   Cyber Competition Edition  |  v2.0
# ============================================================

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

REPORT="detective_report_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

# Tee everything to file AND screen
exec > >(tee -a "$REPORT") 2>&1

# ── helpers ──────────────────────────────────────────────────
alert() { echo -e "${RED}${BOLD}[!!!] $1${RESET}"; }
warn()  { echo -e "${YELLOW}[*]   $1${RESET}"; }
info()  { echo -e "${GREEN}[+]   $1${RESET}"; }
note()  { echo -e "${CYAN}[-]   $1${RESET}"; }

section() {
    echo ""
    echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════╗${RESET}"
    printf "${BOLD}${MAGENTA}║  %-56s  ║${RESET}\n" "$1"
    echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

ALERT_COUNT=0
flag() { ALERT_COUNT=$((ALERT_COUNT + 1)); alert "$1"; }

# ── banner ───────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat << 'EOF'
  ____       _            _   _
 |  _ \  ___| |_ ___  ___| |_(_)_   _____
 | | | |/ _ \ __/ _ \/ __| __| \ \ / / _ \
 | |_| |  __/ ||  __/ (__| |_| |\ V /  __/
 |____/ \___|\__\___|\___|\__|_| \_/ \___|
EOF
echo -e "${RESET}"
echo -e "${BOLD}  Backdoor & Compromise Detector  |  $(date)${RESET}"
echo -e "${BOLD}  Host: $(hostname)  |  User: $(whoami)  |  Kernel: $(uname -r)${RESET}"
echo -e "${BOLD}  Report → $REPORT${RESET}"
echo ""

# ── detect OS ────────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="$ID"
    OS_LIKE="$ID_LIKE"
    OS_NAME="$PRETTY_NAME"
else
    OS_ID="unknown"
fi

info "OS: $OS_NAME"
IS_DEB=0; IS_RPM=0
[[ "$OS_ID" =~ (ubuntu|debian|kali|mint) || "$OS_LIKE" =~ debian ]] && IS_DEB=1
[[ "$OS_ID" =~ (rocky|rhel|centos|fedora|alma) || "$OS_LIKE" =~ (rhel|fedora) ]] && IS_RPM=1

# ============================================================
# 1. SHELL BINARY INTEGRITY
#    nologin / false are common targets - they may drop a shell
# ============================================================
section "1. SHELL BINARY INTEGRITY (nologin / false checks)"

SHELL_BINS=(
    /sbin/nologin
    /usr/sbin/nologin
    /bin/nologin
    /usr/bin/nologin
    /bin/false
    /usr/bin/false
)

for bin in "${SHELL_BINS[@]}"; do
    [ -f "$bin" ] || continue

    ftype=$(file "$bin" 2>/dev/null)
    note "Checking $bin  →  $ftype"

    # A real nologin/false should NOT contain shell-spawning strings
    suspicious_strings=$(strings "$bin" 2>/dev/null \
        | grep -iE '(/bin/sh|/bin/bash|/bin/dash|exec.*shell|pts/|socat|nc |netcat|python|perl|ruby|lua)')

    if [ -n "$suspicious_strings" ]; then
        flag "$bin contains shell-related strings — LIKELY BACKDOOR!"
        echo "$suspicious_strings" | sed 's/^/          /'
    else
        info "$bin looks clean (no shell strings)"
    fi

    echo "    SHA256: $(sha256sum "$bin" 2>/dev/null | awk '{print $1}')"
done

echo ""
note "/etc/shells contents:"
cat /etc/shells 2>/dev/null

# Warn about any entry in /etc/shells that is not a standard interactive shell
while IFS= read -r sh; do
    [[ "$sh" =~ ^# || -z "$sh" ]] && continue
    [[ "$sh" =~ (nologin|false) ]] && flag "$sh is listed in /etc/shells — shells restricted by nologin/false may now be interactive!"
done < /etc/shells 2>/dev/null

# ============================================================
# 2. /etc/passwd ANALYSIS
# ============================================================
section "2. /etc/passwd ANALYSIS"

note "UID 0 accounts (should ONLY be root):"
awk -F: '($3==0){print}' /etc/passwd | while read -r line; do
    uname=$(echo "$line" | cut -d: -f1)
    [ "$uname" != "root" ] && flag "Non-root UID 0 account: $line" || info "$line"
done

echo ""
note "Accounts with interactive shells (excluding nologin/false/sync/halt/shutdown):"
grep -vE ':(nologin|false|sync|halt|shutdown|git-shell)$' /etc/passwd \
    | awk -F: '$3>=1000 || $3==0 {print}' \
    | while read -r line; do
        warn "$line"
    done

echo ""
note "Accounts with home directories in suspicious locations (/tmp, /dev, /var/tmp):"
awk -F: '($6~/^\/tmp|^\/dev|^\/var\/tmp/){print}' /etc/passwd \
    | while read -r line; do flag "$line"; done

echo ""
note "Locked vs unlocked accounts (shadow — may need root):"
if [ -r /etc/shadow ]; then
    awk -F: '($2 !~ /^[!*]/ && $2 != "" && $1 != "root"){print "  UNLOCKED: "$1}' /etc/shadow \
        | while read -r line; do warn "$line"; done
else
    warn "/etc/shadow not readable (run as root for full check)"
fi

# ============================================================
# 3. PACKAGE INTEGRITY
# ============================================================
section "3. PACKAGE INTEGRITY CHECK"

if [ $IS_DEB -eq 1 ]; then
    if command -v debsums &>/dev/null; then
        info "Running debsums -s (silent = only failures)..."
        warn "This may take 1-2 minutes..."
        debsums_out=$(debsums -s 2>&1)
        if [ -n "$debsums_out" ]; then
            flag "MODIFIED PACKAGE FILES DETECTED:"
            echo "$debsums_out" | while read -r line; do alert "  $line"; done
        else
            info "debsums: No modifications detected"
        fi
    else
        warn "debsums not installed.  apt-get install -y debsums"
        info "Falling back to dpkg -V..."
        dpkg -V 2>/dev/null | while read -r line; do
            warn "dpkg -V: $line"
        done
    fi

elif [ $IS_RPM -eq 1 ]; then
    info "Running rpm -Va (verify all packages)..."
    warn "This may take 1-2 minutes..."
    rpm -Va 2>/dev/null | while read -r line; do
        flags=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | awk '{print $NF}')
        echo "$flags" | grep -q "5" && flag "MD5 MISMATCH:    $line" && continue
        echo "$flags" | grep -q "S" && flag "SIZE CHANGED:    $line" && continue
        echo "$flags" | grep -q "M" && flag "MODE CHANGED:    $line" && continue
        warn "MODIFIED:        $line"
    done
    info "rpm -Va complete"
fi

# ============================================================
# 3a. PACKAGE MANAGER PRIORITY SABOTAGE
# ============================================================
section "3a. PACKAGE MANAGER PRIORITY / PIN SABOTAGE"

if [ $IS_DEB -eq 1 ]; then
    note "Checking APT pins in /etc/apt/preferences and preferences.d/ ..."
    for f in /etc/apt/preferences $(find /etc/apt/preferences.d -type f 2>/dev/null); do
        [ -f "$f" ] || continue
        echo "  --- $f ---"
        cat "$f"
        if grep -qP 'Pin-Priority\s*:\s*-' "$f"; then
            flag "NEGATIVE Pin-Priority in $f → important package(s) blocked from install/upgrade!"
            grep -P 'Pin-Priority\s*:\s*-' "$f"
        fi
    done

elif [ $IS_RPM -eq 1 ]; then
    note "Checking DNF/YUM repo priorities in /etc/yum.repos.d/ ..."
    for f in /etc/yum.repos.d/*.repo; do
        [ -f "$f" ] || continue
        if grep -qi "priority" "$f"; then
            echo "  --- $f ---"
            grep -i "priority" "$f"
            grep -qP 'priority\s*=\s*(-|\d{3,})' "$f" && flag "Suspicious priority value in $f"
        fi
    done
fi

# ============================================================
# 4. NETWORK CONNECTIONS & LISTENING PORTS
# ============================================================
section "4. NETWORK CONNECTIONS"

note "All listening ports + owning process:"
if command -v ss &>/dev/null; then
    ss -tulnp
else
    netstat -tulnp 2>/dev/null
fi

echo ""
note "Established connections (reverse shells often show up here):"
if command -v ss &>/dev/null; then
    ss -tnp | grep -i ESTAB
else
    netstat -tnp 2>/dev/null | grep -i ESTAB
fi

echo ""
note "Flagging uncommon listening ports..."
EXPECTED_PORTS="22 80 443 25 53 110 143 587 993 995 3306 5432 6379 8080 8443 9090"
if command -v ss &>/dev/null; then
    PORT_LIST=$(ss -tlnp | awk 'NR>1 {print $4}' | grep -oP '(?<=:)\d+' | sort -nu)
else
    PORT_LIST=$(netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}' | grep -oP '(?<=:)\d+' | sort -nu)
fi
for port in $PORT_LIST; do
    if ! echo "$EXPECTED_PORTS" | grep -wq "$port"; then
        warn "Unexpected listening port: $port"
        command -v ss &>/dev/null \
            && ss -tlnp | grep ":$port " \
            || netstat -tlnp 2>/dev/null | grep ":$port "
    fi
done

echo ""
note "Cross-checking /proc/net/tcp against ss (rootkit port hiding)..."
# /proc/net/tcp is harder for a rootkit to fake than ss output
PROC_PORTS=$(awk 'NR>1 && $4=="0A" {printf "%d\n", strtonum("0x" substr($2, index($2,":")+1))}' \
    /proc/net/tcp /proc/net/tcp6 2>/dev/null | sort -nu)
for port in $PROC_PORTS; do
    if ! echo "$PORT_LIST" | grep -qw "$port"; then
        flag "Port $port visible in /proc/net/tcp but NOT in ss output — possible rootkit hiding!"
    fi
done

# ============================================================
# 5. PROCESS ANALYSIS
# ============================================================
section "5. SUSPICIOUS PROCESS ANALYSIS"

note "Full process listing:"
ps auxf 2>/dev/null || ps aux

echo ""
note "Scanning for known-suspicious process patterns..."
SUSPECT_PATTERNS=(
    "watershell"
    "nc -"
    "ncat "
    "netcat"
    "bash -i"
    "sh -i"
    "python[23]? -c"
    "perl -e"
    "ruby -e"
    "socat"
    "mkfifo"
    "meterpreter"
    "mettle"
    "reverse.?shell"
    "backdoor"
    "bindshell"
    "0\.0\.0\.0.*shell"
    "/tmp/[a-zA-Z0-9]"
    "/dev/shm/"
    "xterm.*-display"
    "base64.*-d.*sh"
    "busybox.*nc"
)

for pat in "${SUSPECT_PATTERNS[@]}"; do
    hits=$(ps aux | grep -iE "$pat" | grep -v grep | grep -v detective.sh)
    [ -n "$hits" ] && flag "Matched pattern '$pat':" && echo "$hits" | sed 's/^/    /'
done

echo ""
note "Processes running from /tmp, /dev/shm, /var/tmp (common malware staging)..."
for pid in /proc/[0-9]*/exe; do
    target=$(readlink "$pid" 2>/dev/null)
    if echo "$target" | grep -qE '^(/tmp|/dev/shm|/var/tmp)'; then
        pidnum=$(echo "$pid" | grep -oP '\d+')
        flag "Process PID $pidnum running from $target"
        ps -p "$pidnum" -o pid,user,cmd --no-headers 2>/dev/null
    fi
done

echo ""
note "Processes with deleted executable on disk (fileless malware indicator)..."
for pid in /proc/[0-9]*/exe; do
    if readlink "$pid" 2>/dev/null | grep -q "(deleted)"; then
        pidnum=$(echo "$pid" | grep -oP '\d+')
        exepath=$(readlink "$pid" 2>/dev/null)
        flag "PID $pidnum running from DELETED binary: $exepath"
        ps -p "$pidnum" -o pid,user,cmd --no-headers 2>/dev/null
    fi
done

echo ""
note "Comparing /proc PIDs vs ps (rootkit hidden process check)..."
PROC_PIDS=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
PS_PIDS=$(ps -e -o pid= | tr -d ' ' | sort -n)
HIDDEN=0
for pid in $PROC_PIDS; do
    if ! echo "$PS_PIDS" | grep -qx "$pid"; then
        cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        [ -n "$cmd" ] && flag "PID $pid in /proc but hidden from ps: $cmd" && HIDDEN=1
    fi
done
[ $HIDDEN -eq 0 ] && info "No hidden processes detected"

# ============================================================
# 6. SUID / SGID BINARIES & CAPABILITIES
# ============================================================
section "6. SUID / SGID BINARIES & LINUX CAPABILITIES"

note "SUID binaries (can execute as root — check for unexpected ones):"
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
    warn "SUID: $f  $(ls -la "$f" 2>/dev/null | awk '{print $1, $3, $4}')"
done

echo ""
note "World-writable SUID/SGID binaries (critical!):"
find / -xdev \( -perm -4000 -o -perm -2000 \) -perm -0002 -type f 2>/dev/null | while read -r f; do
    flag "World-writable + SUID/SGID: $f"
done

echo ""
note "Linux capabilities on binaries (getcap) — watch for cap_setuid, cap_net_raw, etc.:"
if command -v getcap &>/dev/null; then
    getcap -r / 2>/dev/null | while read -r line; do
        echo "$line" | grep -qiE '(cap_setuid|cap_setgid|cap_sys_admin|cap_net_bind_service|cap_dac_override)' \
            && flag "Elevated capability: $line" \
            || warn "Capability: $line"
    done
else
    warn "getcap not found (apt install libcap2-bin / dnf install libcap)"
fi

# ============================================================
# 7. RECENTLY MODIFIED FILES
# ============================================================
section "7. RECENTLY MODIFIED SYSTEM FILES (since boot / last 24h)"

note "Modified files in key system directories (since PID 1 started = since boot):"
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /lib /lib64 \
     /usr/lib /usr/lib64 /etc -xdev -newer /proc/1 -type f 2>/dev/null \
     | head -60 | while read -r f; do
    warn "MODIFIED: $f  ($(stat -c '%y' "$f" 2>/dev/null | cut -d. -f1))"
done

echo ""
note "Files in /tmp, /dev/shm, /var/tmp (malware staging areas):"
find /tmp /dev/shm /var/tmp -type f 2>/dev/null | while read -r f; do
    warn "Staging area file: $(ls -la "$f" 2>/dev/null)"
    ft=$(file "$f" 2>/dev/null | grep -i 'ELF\|script\|shell')
    [ -n "$ft" ] && flag "EXECUTABLE in staging area: $f → $ft"
done

echo ""
note "World-writable directories (can be used to stage attacks):"
find / -xdev -type d -perm -0002 2>/dev/null | grep -vE '^(/proc|/sys|/dev)' | while read -r d; do
    warn "World-writable dir: $d  $(ls -lad "$d" 2>/dev/null | awk '{print $1,$3,$4}')"
done

echo ""
note "Immutable file attribute check (lsattr) on key dirs — attackers may use chattr +i to lock backdoors:"
if command -v lsattr &>/dev/null; then
    lsattr /etc /bin /sbin /usr/bin /usr/sbin 2>/dev/null | grep -v "^-" | grep -v "^lsattr:" | while read -r line; do
        attrs=$(echo "$line" | awk '{print $1}')
        fname=$(echo "$line" | awk '{print $2}')
        echo "$attrs" | grep -qE '[iau]' && flag "Unusual inode attribute '$attrs' on $fname" || true
    done
else
    warn "lsattr not found"
fi

# ============================================================
# 8. CRON JOBS & PERSISTENCE
# ============================================================
section "8. CRON JOBS & PERSISTENCE"

note "System crontab + cron.d:"
cat /etc/crontab 2>/dev/null
for f in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* \
         /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] || continue
    echo ""; echo "  --- $f ---"; cat "$f"
done

echo ""
note "All user crontabs:"
for u in $(cut -d: -f1 /etc/passwd); do
    ctab=$(crontab -u "$u" -l 2>/dev/null)
    [ -n "$ctab" ] && echo "  [$u crontab]" && echo "$ctab"
done

echo ""
note "at / batch jobs (atq):"
if command -v atq &>/dev/null; then
    atq 2>/dev/null && atq 2>/dev/null | awk '{print $1}' | while read -r job; do
        echo "  --- at job $job ---"
        at -c "$job" 2>/dev/null | tail -20
    done || info "No at jobs queued"
else
    warn "atq not found"
fi

echo ""
note "Enabled systemd services (spot unfamiliar ones):"
systemctl list-unit-files --type=service --state=enabled 2>/dev/null

echo ""
note "Enabled systemd TIMERS (another persistence vector — often missed!):"
systemctl list-unit-files --type=timer --state=enabled 2>/dev/null
systemctl list-timers --all 2>/dev/null

echo ""
note "Scanning systemd unit files for suspicious ExecStart commands..."
find /etc/systemd /usr/lib/systemd /lib/systemd -name "*.service" 2>/dev/null | while read -r svc; do
    if grep -qiE '(bash -i|nc |socat|mkfifo|wget.*sh|curl.*sh|python.*-c|/tmp/|/dev/shm/)' "$svc" 2>/dev/null; then
        flag "Suspicious service: $svc"
        grep -iE '(Exec|bash|nc |socat|python|perl|wget|curl)' "$svc"
    fi
done

echo ""
note "/etc/rc.local:"
cat /etc/rc.local 2>/dev/null || echo "  (not found)"

echo ""
note "/etc/profile.d/ scripts (global login persistence):"
for f in /etc/profile.d/*.sh; do
    [ -f "$f" ] || continue
    echo "  --- $f ---"
    cat "$f"
    grep -qiE '(wget|curl|nc |bash -i|socat|/tmp/|/dev/shm/)' "$f" \
        && flag "Suspicious content in $f"
done

echo ""
note "/etc/profile and /etc/environment (check for LD_PRELOAD / PATH injection):"
for f in /etc/profile /etc/environment /etc/bash.bashrc; do
    [ -f "$f" ] || continue
    echo "  --- $f ---"
    cat "$f"
    grep -qiE '(LD_PRELOAD|LD_LIBRARY_PATH)' "$f" \
        && flag "LD_PRELOAD/LD_LIBRARY_PATH found in $f"
    grep -qiE 'PATH=.*(/tmp|/dev/shm|/var/tmp)' "$f" \
        && flag "Suspicious PATH entry in $f"
done

echo ""
note "Root & ALL user shell init files (.bashrc, .profile, .bash_profile, .zshrc):"
while IFS=: read -r user _ _ _ _ homedir _; do
    for f in "$homedir/.bashrc" "$homedir/.profile" "$homedir/.bash_profile" \
              "$homedir/.zshrc" "$homedir/.zprofile" "$homedir/.bash_logout"; do
        [ -f "$f" ] || continue
        echo "  --- [$user] $f ---"
        cat "$f"
        grep -qiE '(wget|curl|nc |bash -i|socat|/tmp/|/dev/shm/|LD_PRELOAD)' "$f" \
            && flag "Suspicious content in $f"
    done
done < /etc/passwd

# ============================================================
# 9. SSH BACKDOORS
# ============================================================
section "9. SSH BACKDOOR ANALYSIS"

note "Checking authorized_keys for all users..."
while IFS=: read -r user _ _ _ _ homedir _; do
    ak="$homedir/.ssh/authorized_keys"
    [ -f "$ak" ] || continue
    echo "  --- $user → $ak ---"
    cat "$ak"
    echo ""
    # Flag keys with command= restrictions or unusual options
    grep -qE '(no-pty|command=|tunnel=|from=)' "$ak" \
        && warn "Key with forced command or restriction in $ak (review carefully)"
done < /etc/passwd

echo ""
note "Checking .ssh/config files for ProxyJump/ProxyCommand (lateral movement):"
while IFS=: read -r user _ _ _ _ homedir _; do
    cfg="$homedir/.ssh/config"
    [ -f "$cfg" ] || continue
    echo "  --- [$user] $cfg ---"
    cat "$cfg"
    grep -qiE '(ProxyCommand|ProxyJump)' "$cfg" \
        && warn "ProxyCommand/ProxyJump in $cfg — review for tunneling"
done < /etc/passwd

echo ""
note "sshd_config (active directives only):"
grep -vE '^\s*(#|$)' /etc/ssh/sshd_config 2>/dev/null

if grep -qiE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
    flag "PermitRootLogin YES is set in sshd_config!"
fi
if grep -qiE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
    warn "PasswordAuthentication YES — brute force possible"
fi
if grep -qiE '^\s*AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null; then
    note "AuthorizedKeysFile is customized:"
    grep -iE '^\s*AuthorizedKeysFile' /etc/ssh/sshd_config
    grep -iE 'AuthorizedKeysFile.*(\/tmp|\/dev|\.\./)' /etc/ssh/sshd_config \
        && flag "AuthorizedKeysFile points to suspicious path!"
fi
if grep -qiE '^\s*Match' /etc/ssh/sshd_config 2>/dev/null; then
    note "Match blocks found in sshd_config — review for per-user overrides:"
    grep -A5 '^\s*Match' /etc/ssh/sshd_config
fi

# ============================================================
# 10. ROOTKIT INDICATORS (LD_PRELOAD / PAM / kernel modules)
# ============================================================
section "10. ROOTKIT INDICATORS"

note "Checking /etc/ld.so.preload (used by rootkits to inject shared libs)..."
if [ -f /etc/ld.so.preload ]; then
    flag "/etc/ld.so.preload EXISTS — contents:"
    cat /etc/ld.so.preload
else
    info "/etc/ld.so.preload does not exist (good)"
fi

echo ""
note "Checking /etc/ld.so.conf.d/ for injected library paths..."
for f in /etc/ld.so.conf /etc/ld.so.conf.d/*.conf; do
    [ -f "$f" ] || continue
    echo "  --- $f ---"
    cat "$f"
    grep -qiE '(/tmp|/dev/shm|/var/tmp|/home)' "$f" \
        && flag "Suspicious library path in $f"
done

echo ""
note "Checking LD_PRELOAD in environment..."
[ -n "$LD_PRELOAD" ] && flag "LD_PRELOAD is set: $LD_PRELOAD" || info "LD_PRELOAD not set in this shell"

echo ""
note "Loaded kernel modules:"
lsmod | sort

echo ""
note "Kernel modules not in standard module directory (possible LKM rootkit)..."
if command -v modinfo &>/dev/null; then
    lsmod | awk 'NR>1 {print $1}' | while read -r mod; do
        path=$(modinfo -n "$mod" 2>/dev/null)
        if [ -n "$path" ] && ! echo "$path" | grep -qE '^/lib/modules|^/usr/lib/modules'; then
            flag "Module '$mod' loaded from unusual path: $path"
        fi
    done
fi

echo ""
note "PAM configuration files (check for pam_exec or unusual entries)..."
grep -rn "pam_exec\|pam_python\|pam_script" /etc/pam.d/ 2>/dev/null | while read -r line; do
    flag "Suspicious PAM entry: $line"
done

echo ""
note "Checking for PAM keylogger (pam_exec writing passwords to a file)..."
grep -rn "pam_exec" /etc/pam.d/ 2>/dev/null | while read -r line; do
    script=$(echo "$line" | grep -oP '(?<=pam_exec\.so\s)(\S+)' | head -1)
    [ -f "$script" ] && warn "pam_exec script exists: $script" && cat "$script"
done

# ============================================================
# 11. SUDOERS ANALYSIS
# ============================================================
section "11. SUDOERS ANALYSIS"

note "/etc/sudoers:"
cat /etc/sudoers 2>/dev/null
grep -qiE 'NOPASSWD.*ALL|ALL.*NOPASSWD' /etc/sudoers 2>/dev/null \
    && flag "Unrestricted NOPASSWD ALL in /etc/sudoers!"

echo ""
note "/etc/sudoers.d/ entries:"
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    echo "  --- $f ---"
    cat "$f"
    grep -qi 'NOPASSWD.*ALL\|ALL.*NOPASSWD' "$f" && flag "Unrestricted NOPASSWD ALL in $f"
done

echo ""
note "sudo -l (what can current user do):"
sudo -l 2>/dev/null || warn "sudo -l failed (not in sudoers or requires password)"

# ============================================================
# 12. WATERSHELL / KNOWN MALWARE SEARCH
# ============================================================
section "12. KNOWN MALWARE BINARY SEARCH"

note "Searching for 'watershell' (port-knocking bypass shell)..."
find / -xdev -name "watershell*" 2>/dev/null | while read -r f; do
    flag "WATERSHELL FOUND: $f"
    ls -la "$f"; file "$f"
done

echo ""
note "Searching for ELF executables in unusual locations..."
find /tmp /dev/shm /var/tmp /home -type f 2>/dev/null | while read -r f; do
    if file "$f" 2>/dev/null | grep -q "ELF"; then
        flag "ELF BINARY in suspicious path: $f"
        ls -la "$f"; file "$f"
    fi
done

echo ""
note "Searching for scripts with embedded reverse shell patterns..."
grep -rlE '(bash -i|/dev/tcp|socat.*exec|nc.*-e|mkfifo.*nc)' \
     /etc /tmp /var/tmp /home /root /usr/local 2>/dev/null | while read -r f; do
    flag "Reverse shell pattern in: $f"
    grep -nE '(bash -i|/dev/tcp|socat.*exec|nc.*-e|mkfifo.*nc)' "$f" | head -5
done

echo ""
note "Searching for base64-encoded payloads in scripts (obfuscated commands)..."
grep -rlE 'base64.*-d|echo.*\|.*bash|eval.*\$\(' \
     /etc /tmp /var/tmp /home /root /usr/local 2>/dev/null | while read -r f; do
    flag "Possible obfuscated payload in: $f"
    grep -nE 'base64.*-d|echo.*\|.*bash|eval.*\$\(' "$f" | head -5
done

# ============================================================
# 13. /etc/hosts & DNS TAMPERING
# ============================================================
section "13. /etc/hosts & DNS TAMPERING"

note "/etc/hosts (look for redirected domains — update servers, monitoring, etc.):"
cat /etc/hosts
echo ""
note "Flagging non-localhost entries that override common hostnames..."
grep -vE '^(#|$|\s*127\.|::1|fe80)' /etc/hosts | while read -r line; do
    warn "Non-local /etc/hosts entry: $line"
    echo "$line" | grep -qiE '(google|ubuntu|centos|rocky|rhel|fedora|debian|apt|yum|dnf|update|security|ppa|mirror)' \
        && flag "Possible update-server redirect: $line"
done

echo ""
note "DNS resolver config (/etc/resolv.conf):"
cat /etc/resolv.conf 2>/dev/null

echo ""
note "nsswitch.conf (controls lookup order — 'files' before 'dns' is default):"
cat /etc/nsswitch.conf 2>/dev/null
grep 'hosts:' /etc/nsswitch.conf 2>/dev/null | grep -v 'files.*dns' \
    && warn "Non-standard hosts lookup order in nsswitch.conf — review!"

# ============================================================
# 14. FIREWALL INTEGRITY & MALICIOUS RULE DETECTION
#     iptables binary may be sabotaged — use multiple read paths
# ============================================================
section "14. FIREWALL INTEGRITY & MALICIOUS RULE DETECTION"

# ── Step 0: Inventory — what firewall tooling exists at all? ─
note "Scanning for installed firewall tooling..."
FIREWALL_TOOLS=()
for tool in iptables iptables-legacy iptables-nft iptables-save nft firewall-cmd ufw; do
    command -v "$tool" &>/dev/null && FIREWALL_TOOLS+=("$tool") && info "Found: $tool → $(command -v "$tool")"
done

if [ ${#FIREWALL_TOOLS[@]} -eq 0 ]; then
    flag "NO firewall tooling found on this system whatsoever!"
    flag "Machine may be completely unfiltered — all ports are exposed to the network."
    warn "Skipping tool-based firewall checks. Falling back to kernel-only checks below."
else
    info "Firewall tools present: ${FIREWALL_TOOLS[*]}"
fi

# ── Kernel-level netfilter check (works even with zero tools) ─
echo ""
note "Kernel netfilter module status (no userspace tools required)..."
if [ -f /proc/net/ip_tables_names ]; then
    tables=$(cat /proc/net/ip_tables_names 2>/dev/null)
    if [ -n "$tables" ]; then
        info "iptables kernel tables active: $tables"
        echo "$tables" | grep -qw "nat" && warn "NAT table is loaded — check PREROUTING/OUTPUT for redirects"
    else
        flag "iptables kernel module loaded but NO tables active — firewall is effectively disabled!"
    fi
else
    warn "/proc/net/ip_tables_names absent — ip_tables kernel module not loaded at all"
fi

if [ -f /proc/net/nf_conntrack ]; then
    total=$(wc -l < /proc/net/nf_conntrack 2>/dev/null)
    note "conntrack module loaded — $total active connection entries"
    hits=$(grep -i 'dnat\|redirect' /proc/net/nf_conntrack 2>/dev/null)
    [ -n "$hits" ] && flag "Active conntrack DNAT/redirect entries (kernel-level — unfakeable):" \
        && echo "$hits" || info "No DNAT/redirect entries in conntrack table"
else
    note "/proc/net/nf_conntrack absent (conntrack module not loaded)"
fi

# Check for nftables kernel support independently of nft binary
if [ -d /proc/net/netfilter ] || ls /sys/kernel/debug/nft* 2>/dev/null | head -1 &>/dev/null; then
    info "nftables kernel support detected"
fi

if [ ${#FIREWALL_TOOLS[@]} -gt 0 ]; then

# ── Step 1: iptables binary integrity ────────────────────────
note "Checking iptables binary integrity (may be replaced by attacker)..."
ipt_found=0
for ipt_bin in /sbin/iptables /usr/sbin/iptables /bin/iptables /usr/bin/iptables; do
    [ -f "$ipt_bin" ] || continue
    ipt_found=1
    real=$(readlink -f "$ipt_bin" 2>/dev/null)
    ftype=$(file "$real" 2>/dev/null)
    echo "  $ipt_bin → $real"
    echo "  SHA256: $(sha256sum "$real" 2>/dev/null | awk '{print $1}')"
    echo "  Type:   $ftype"
    echo "$ftype" | grep -qiv 'ELF\|shell script\|Python\|symbolic' \
        && flag "iptables binary has unexpected file type: $ftype"
    strings "$real" 2>/dev/null | grep -qiE '(bash -i|/dev/tcp|socat|nc -e|mkfifo)' \
        && flag "BACKDOOR STRINGS in iptables binary $real!"
done
[ $ipt_found -eq 0 ] && note "No iptables binary found in standard paths"

# ── Step 2: Identify available iptables variants ─────────────
IPT_LEGACY=""
IPT_NFT=""
for c in iptables-legacy /usr/sbin/iptables-legacy /sbin/iptables-legacy; do
    command -v "$c" &>/dev/null && IPT_LEGACY=$(command -v "$c") && break
done
for c in iptables-nft /usr/sbin/iptables-nft /sbin/iptables-nft; do
    command -v "$c" &>/dev/null && IPT_NFT=$(command -v "$c") && break
done
IPT_CMD=""
[ -n "$IPT_LEGACY" ] && IPT_CMD="$IPT_LEGACY" && info "Using iptables-legacy: $IPT_LEGACY"
[ -z "$IPT_CMD" ] && [ -n "$IPT_NFT" ] && IPT_CMD="$IPT_NFT" && info "Using iptables-nft: $IPT_NFT"
[ -z "$IPT_CMD" ] && command -v iptables &>/dev/null \
    && IPT_CMD="iptables" \
    && warn "Using plain iptables (variant unknown — output may be unreliable if binary is tampered)"

# ── Step 3: Analyze iptables rules (detection focused) ───────
analyze_ipt() {
    local cmd="$1" label="$2"
    echo ""
    note "[$label] Default chain policies (INPUT/FORWARD ACCEPT = no firewall!):"
    $cmd -L -n 2>/dev/null | grep -E '^Chain' | while read -r line; do
        echo "  $line"
        echo "$line" | grep -qE '(INPUT|FORWARD).*policy ACCEPT' \
            && flag "[$label] $line — default-deny not set!"
    done

    echo ""
    note "[$label] NAT PREROUTING (port redirect / traffic hijack rules):"
    out=$($cmd -t nat -L PREROUTING -n --line-numbers 2>/dev/null)
    echo "$out"
    echo "$out" | grep -vE '^(num|target|Chain|$)' | while read -r line; do
        [ -n "$(echo "$line" | tr -d ' ')" ] && flag "[$label] NAT PREROUTING rule active: $line"
    done

    echo ""
    note "[$label] NAT OUTPUT (local traffic redirection):"
    out=$($cmd -t nat -L OUTPUT -n --line-numbers 2>/dev/null)
    echo "$out"
    echo "$out" | grep -vE '^(num|target|Chain|$)' | while read -r line; do
        [ -n "$(echo "$line" | tr -d ' ')" ] && flag "[$label] NAT OUTPUT rule active: $line"
    done

    echo ""
    note "[$label] INPUT ACCEPT rules (inbound allowed traffic):"
    $cmd -L INPUT -n --line-numbers 2>/dev/null | grep -i ACCEPT | while read -r line; do
        warn "[$label] INPUT ACCEPT: $line"
    done

    echo ""
    note "[$label] Full ruleset (for manual review):"
    $cmd -L -n -v 2>/dev/null
    $cmd -t nat -L -n -v 2>/dev/null
    $cmd -t mangle -L -n -v 2>/dev/null
}

if [ -n "$IPT_LEGACY" ] && [ -n "$IPT_NFT" ]; then
    analyze_ipt "$IPT_LEGACY" "iptables-legacy"
    analyze_ipt "$IPT_NFT"    "iptables-nft"
    note "Cross-checking legacy vs nft NAT PREROUTING for discrepancies..."
    legacy_nat=$($IPT_LEGACY -t nat -L PREROUTING -n 2>/dev/null | grep -vE '^(target|Chain|$)')
    nft_nat=$($IPT_NFT       -t nat -L PREROUTING -n 2>/dev/null | grep -vE '^(target|Chain|$)')
    if [ "$legacy_nat" != "$nft_nat" ]; then
        flag "NAT PREROUTING DIFFERS between iptables-legacy and iptables-nft — possible tampering!"
        echo "  legacy output: $legacy_nat"
        echo "  nft    output: $nft_nat"
    else
        info "iptables-legacy and iptables-nft NAT PREROUTING match"
    fi
elif [ -n "$IPT_CMD" ]; then
    analyze_ipt "$IPT_CMD" "iptables"
fi

# ── Step 4: iptables-save (independent read path) ────────────
echo ""
if command -v iptables-save &>/dev/null; then
    note "iptables-save (separate code path from iptables -L — harder to fake consistently):"
    ipt_save=$(iptables-save 2>/dev/null)
    echo "$ipt_save" | grep -v '^#'
    echo "$ipt_save" | grep -qiE '\-j (DNAT|REDIRECT|MASQUERADE)' \
        && flag "iptables-save: NAT/redirect rule present!"
    echo "$ipt_save" | grep -qE ':INPUT ACCEPT|:FORWARD ACCEPT' \
        && flag "iptables-save: INPUT or FORWARD policy is ACCEPT!"
fi

# ── Step 5: nftables (independent of iptables entirely) ──────
echo ""
if command -v nft &>/dev/null; then
    note "nftables via nft (fully independent of iptables binary):"
    nft_out=$(nft list ruleset 2>/dev/null)
    if [ -n "$nft_out" ]; then
        echo "$nft_out"
        echo "$nft_out" | grep -iE '(dnat|redirect|masquerade)' | while read -r line; do
            flag "nft: NAT/redirect rule: $line"
        done
        echo "$nft_out" | grep -iE 'policy accept' | while read -r line; do
            warn "nft: Chain with accept policy: $line"
        done
        echo "$nft_out" | grep -iE '(tcp|udp) dport [0-9]+ (dnat|redirect)' | while read -r line; do
            flag "nft: Port redirect rule: $line"
        done
    else
        info "nft list ruleset returned empty (no nftables rules loaded)"
    fi
fi

# ── Step 6: firewalld (Rocky) ─────────────────────────────────
if command -v firewall-cmd &>/dev/null; then
    echo ""
    note "firewalld active rules:"
    firewall-cmd --state 2>/dev/null
    firewall-cmd --list-all-zones 2>/dev/null
    note "firewalld direct rules (bypass zone policy — attacker favorite):"
    direct=$(firewall-cmd --direct --get-all-rules 2>/dev/null)
    [ -n "$direct" ] \
        && flag "firewalld direct rules present (bypass zone policy):" && echo "$direct" \
        || info "No firewalld direct rules"
fi

# ── Step 7: ufw (Ubuntu) ──────────────────────────────────────
if command -v ufw &>/dev/null; then
    echo ""
    note "ufw status:"
    ufw status verbose 2>/dev/null
    ufw status numbered 2>/dev/null | grep -i ALLOW | while read -r line; do
        warn "ufw ALLOW rule: $line"
    done
fi

else
    warn "No firewall tools present — tool-based checks skipped. See kernel checks above."
fi  # end FIREWALL_TOOLS guard

# ============================================================
# 15. RECENT LOGINS & WTMP
# ============================================================
section "15. LOGIN HISTORY"

note "Recent logins (last):"
last | head -40

echo ""
note "Last login per account (lastlog):"
lastlog 2>/dev/null | grep -v "Never logged in" | head -30

echo ""
note "Failed login attempts:"
journalctl -q --no-pager -n 30 -u sshd 2>/dev/null | grep -iE '(fail|invalid|unauthorized)' \
    || grep -iE '(fail|invalid|unauthorized)' /var/log/auth.log 2>/dev/null | tail -30 \
    || grep -iE '(fail|invalid|unauthorized)' /var/log/secure 2>/dev/null | tail -30

echo ""
note "Checking for cleared/missing history files (sign of anti-forensics)..."
while IFS=: read -r user _ uid _ _ homedir _; do
    [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ] && continue
    for hf in "$homedir/.bash_history" "$homedir/.zsh_history"; do
        if [ -f "$hf" ]; then
            lines=$(wc -l < "$hf" 2>/dev/null)
            [ "$lines" -eq 0 ] && flag "History file $hf is EMPTY — possible anti-forensics"
        else
            # /dev/null symlink trick
            if [ -L "$hf" ]; then
                target=$(readlink "$hf")
                flag "History file $hf is a symlink → $target (anti-forensics!)"
            fi
        fi
    done
done < /etc/passwd

echo ""
note "HISTFILE/HISTSIZE in root environment (disabled history is suspicious):"
echo "  HISTFILE=${HISTFILE:-unset}   HISTSIZE=${HISTSIZE:-unset}   HISTFILESIZE=${HISTFILESIZE:-unset}"
[ "${HISTSIZE:-1}" -eq 0 ] 2>/dev/null && flag "HISTSIZE=0 — command history is disabled!"

# ============================================================
# 16. PSPY — RUNTIME PROCESS MONITORING
# ============================================================
section "16. PSPY — RUNTIME PROCESS MONITOR"

PSPY_BIN=""
for candidate in ./pspy64 ./pspy /opt/pspy /usr/local/bin/pspy; do
    [ -x "$candidate" ] && PSPY_BIN="$candidate" && break
done

if [ -n "$PSPY_BIN" ]; then
    info "pspy found at $PSPY_BIN"
    note "Running pspy for 60 seconds to capture spawned processes..."
    timeout 60 "$PSPY_BIN" --ppid --color=false 2>/dev/null \
        | grep -vE '^(UID|$)' \
        | while read -r line; do
            echo "$line" | grep -qiE '(/tmp/|/dev/shm/|bash -i|nc |socat|python.*-c)' \
                && flag "pspy: $line" \
                || note "pspy: $line"
        done
else
    warn "pspy not found in current directory or common paths."
    echo ""
    echo "  To use pspy, download and place next to this script:"
    echo "    wget -q https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64"
    echo "    chmod +x pspy64 && ./detective.sh"
    echo ""
    echo "  pspy watches ALL processes as they spawn (including cron jobs, scripts run by"
    echo "  other users, and short-lived processes that ps would miss)."
fi

# ============================================================
# FINAL SUMMARY
# ============================================================
echo ""
echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${MAGENTA}║                 INVESTIGATION COMPLETE                   ║${RESET}"
echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${BOLD}${RED}  Total alerts flagged: $ALERT_COUNT${RESET}"
echo ""
echo -e "${BOLD}  Full report saved to:  ${CYAN}$REPORT${RESET}"
echo ""
echo -e "${BOLD}  Cheat sheet — run these manually during comp:${RESET}"
echo "  ┌──────────────────────────────────────────────────────────"
echo "  │  ss -tulnp                      # open ports + process"
echo "  │  ss -tnp | grep ESTAB           # active connections"
echo "  │  ps auxf                        # full process tree"
echo "  │  ls -la /proc/*/exe 2>/dev/null # catch deleted binaries"
echo "  │  debsums -s                     # Debian: changed pkg files"
echo "  │  rpm -Va                        # Rocky: verify packages"
echo "  │  getcap -r / 2>/dev/null        # check capabilities"
echo "  │  find / -perm -4000 -type f     # all SUID binaries"
echo "  │  lsattr /etc /bin /usr/bin      # immutable file attrs"
echo "  │  iptables -t nat -L -n          # check NAT redirects"
echo "  │  last ; lastlog                 # login history"
echo "  │  journalctl -xe                 # recent system logs"
echo "  │  inotifywait -mr /etc /bin      # watch for file changes"
echo "  └──────────────────────────────────────────────────────────"
echo ""
echo -e "${RED}${BOLD}  [!] REMEMBER: /sbin/nologin and /bin/false may be shells!${RESET}"
echo -e "${RED}${BOLD}  [!] Check strings on them and compare SHA256 to known-good.${RESET}"
echo -e "${YELLOW}${BOLD}  [*] Keep running 'ss -tnp' and 'ps aux' throughout the comp.${RESET}"
echo -e "${YELLOW}${BOLD}  [*] If a port you shouldn't have is open → find the process.${RESET}"
echo -e "${YELLOW}${BOLD}  [*] Check iptables NAT rules — port 80 may redirect to a backdoor.${RESET}"
echo ""
