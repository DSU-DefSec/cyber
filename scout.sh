#!/bin/bash
# detective.sh — Competition Backdoor Detector
# Usage: ./detective.sh [-n] [-b] [-u] [-s] [-h]
# No args = run all checks. Silence = clean. Output = problem.

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; B='\033[1m'; R='\033[0m'

FIND_FILE=$(mktemp)

hit() { echo -e "  ${RED}${B}[!!]${R} $*"; echo "$*" >> "$FIND_FILE"; }
warn() { echo -e "  ${YEL}[??]${R} $*"; }
ok()   { echo -e "  ${GRN}[ok]${R} $*"; }
hdr()  { echo -e "\n${B}${CYN}── $1 ──────────────────────────────────────────────────${R}"; }

# ── OS detection ─────────────────────────────────────────────
. /etc/os-release 2>/dev/null
IS_DEB=0; IS_RPM=0
[[ "$ID $ID_LIKE" =~ (ubuntu|debian|kali|mint) ]] && IS_DEB=1
[[ "$ID $ID_LIKE" =~ (rocky|rhel|centos|fedora|alma) ]] && IS_RPM=1

# ── help ─────────────────────────────────────────────────────
usage() {
cat << EOF

${B}detective.sh${R} — Backdoor & Compromise Detector
${CYN}Usage:${R} $(basename "$0") [options]

  No options  Run all checks

  ${B}-n${R}  --network    Suspicious open ports & connections
  ${B}-b${R}  --binaries   Backdoored system binaries (pkg integrity)
  ${B}-u${R}  --users      Odd accounts & SSH authorized_keys
  ${B}-s${R}  --services   Strange systemd units & cron jobs
  ${B}-h${R}  --help       Show this help

${CYN}Examples:${R}
  sudo ./detective.sh           # full scan
  sudo ./detective.sh -n -u     # network + users only
  sudo ./detective.sh --services

EOF
exit 0
}

# ── parse args ───────────────────────────────────────────────
RUN_NET=0; RUN_BIN=0; RUN_USR=0; RUN_SVC=0; RUN_ALL=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--network)  RUN_NET=1; RUN_ALL=0 ;;
        -b|--binaries) RUN_BIN=1; RUN_ALL=0 ;;
        -u|--users)    RUN_USR=1; RUN_ALL=0 ;;
        -s|--services) RUN_SVC=1; RUN_ALL=0 ;;
        -h|--help)     usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
    shift
done

[[ $RUN_ALL -eq 1 ]] && RUN_NET=1 RUN_BIN=1 RUN_USR=1 RUN_SVC=1

echo -e "\n${B}${CYN} DETECTIVE  |  $(hostname)  |  $PRETTY_NAME  |  $(date '+%H:%M %Z %b %d')${R}\n"

# ============================================================
# NETWORK — open ports and live connections
# ============================================================
check_network() {
    hdr "NETWORK"

    # Expected listening ports — tune for your competition
    EXPECTED="20 21 22 25 53 80 110 143 443 465 587 993 995 \
               3306 5432 6379 8080 8443 9090"

    if command -v ss &>/dev/null; then
        LISTEN=$(ss -tlnp 2>/dev/null | tail -n +2)
        ESTAB=$(ss -tnp 2>/dev/null | grep -i estab)
    else
        LISTEN=$(netstat -tlnp 2>/dev/null | tail -n +3)
        ESTAB=$(netstat -tnp 2>/dev/null | grep -i estab)
    fi

    net_hit=0
    while IFS= read -r line; do
        port=$(echo "$line" | grep -oP '(?<=[:\]])(\d+)(?=\s)' | tail -1)
        [[ -z "$port" ]] && continue
        echo "$EXPECTED" | grep -wq "$port" && continue
        pid=$(echo "$line" | grep -oP 'pid=\K\d+')
        bin=$([[ -n "$pid" ]] && readlink /proc/"$pid"/exe 2>/dev/null || echo "unknown")
        hit "Unexpected listener :$port  →  $bin"
        net_hit=1
    done <<< "$LISTEN"
    [[ $net_hit -eq 0 ]] && ok "No unexpected listening ports"

    # Outbound established — reverse shells phone home
    if [[ -n "$ESTAB" ]]; then
        warn "Established outbound connections (verify each):"
        echo "$ESTAB" | while IFS= read -r line; do
            remote=$(echo "$line" | awk '{print $5}')
            proc=$(echo "$line" | grep -oP '"[^"]*"' | head -1)
            echo "         $remote  $proc"
        done
    else
        ok "No established non-loopback connections"
    fi
}

# ============================================================
# BINARIES — package integrity + staging-area ELFs
# ============================================================
check_binaries() {
    hdr "SYSTEM BINARY INTEGRITY"

    if [[ $IS_DEB -eq 1 ]]; then
        if command -v debsums &>/dev/null; then
            mapfile -t fails < <(debsums -s 2>/dev/null)
            if [[ ${#fails[@]} -gt 0 ]]; then
                for f in "${fails[@]}"; do hit "debsums FAIL: $f"; done
            else
                ok "debsums — all package files verified clean"
            fi
        else
            warn "debsums not installed (apt install debsums); using dpkg -V"
            mapfile -t fails < <(dpkg -V 2>/dev/null | grep -v '^$')
            [[ ${#fails[@]} -gt 0 ]] \
                && for f in "${fails[@]}"; do hit "dpkg -V: $f"; done \
                || ok "dpkg -V — no changes detected"
        fi

    elif [[ $IS_RPM -eq 1 ]]; then
        # Only checksum/size/mode changes; skip config-file mtime noise
        mapfile -t fails < <(
            rpm -Va 2>/dev/null \
            | grep -vE '\s+c\s+' \
            | grep -E '^.{0,8}[5SM]'
        )
        if [[ ${#fails[@]} -gt 0 ]]; then
            for f in "${fails[@]}"; do hit "rpm -Va FAIL: $f"; done
        else
            ok "rpm -Va — no binary/library modifications detected"
        fi
    else
        warn "Could not detect package manager; skipping integrity check"
    fi

    # nologin/false: verify via pkg manager, then check for denial message string
    hdr "SHELL BINARY INTEGRITY  (nologin / false)"
    shell_hit=0
    for bin in /sbin/nologin /usr/sbin/nologin /bin/nologin \
               /usr/bin/nologin /bin/false /usr/bin/false; do
        [[ -f "$bin" ]] || continue

        # Package manager verdict
        if [[ $IS_DEB -eq 1 ]] && command -v debsums &>/dev/null; then
            debsums -s 2>/dev/null | grep -q "$bin" \
                && hit "$bin FAILED debsums — binary tampered!" \
                && shell_hit=1 && continue
        elif [[ $IS_RPM -eq 1 ]]; then
            rpmout=$(rpm -Vf "$bin" 2>/dev/null | grep -v '^$')
            echo "$rpmout" | grep -qE '^.{0,8}[5SM]' \
                && hit "$bin FAILED rpm check: $rpmout" \
                && shell_hit=1 && continue
        fi

        # nologin must contain its own denial message string
        if echo "$bin" | grep -q nologin; then
            strings "$bin" 2>/dev/null | grep -qiE '(not available|not allowed|account|This account)' \
                || { hit "$bin missing denial message strings — possible shell substitution"; shell_hit=1; continue; }
        fi

        ok "$bin  [sha256: $(sha256sum "$bin" 2>/dev/null | cut -c1-16)...]"
    done

    # /etc/shells must not list nologin/false as interactive
    if grep -qE '^/(s?bin|usr/(s?bin)?)/(nologin|false)$' /etc/shells 2>/dev/null; then
        hit "/etc/shells lists nologin or false — those accounts may get interactive shells"
        grep -E '^/(s?bin|usr/(s?bin)?)/(nologin|false)$' /etc/shells | sed 's/^/         /'
        shell_hit=1
    fi
    [[ $shell_hit -eq 0 ]] && ok "/etc/shells — no nologin/false listed as interactive"

    # ELF executables sitting in staging directories (classic malware drop)
    hdr "ELF BINARIES IN STAGING DIRS  (/tmp /dev/shm /var/tmp)"
    staging_hit=0
    while IFS= read -r f; do
        file "$f" 2>/dev/null | grep -q "ELF" || continue
        hit "ELF binary in staging dir: $f  ($(ls -lah "$f" 2>/dev/null | awk '{print $1,$5}'))"
        staging_hit=1
    done < <(find /tmp /dev/shm /var/tmp -type f 2>/dev/null)
    [[ $staging_hit -eq 0 ]] && ok "No ELF binaries found in staging directories"
}

# ============================================================
# USERS — accounts, UID 0, SSH authorized_keys
# ============================================================
check_users() {
    hdr "USER ACCOUNTS"
    usr_hit=0

    # Extra UID 0
    while IFS= read -r line; do
        hit "Extra UID 0 account: $line"
        usr_hit=1
    done < <(awk -F: '($3==0 && $1!="root"){print}' /etc/passwd)

    # Accounts with interactive shells that shouldn't have them
    while IFS=: read -r user _ uid gid _ homedir shell; do
        [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && continue  # skip system accounts
        [[ "$shell" =~ (nologin|false|sync|halt|shutdown) ]] && continue
        [[ -z "$shell" ]] && continue
        warn "Interactive shell account:  $user  (uid=$uid  shell=$shell)"
    done < /etc/passwd
    [[ $usr_hit -eq 0 ]] && ok "No extra UID 0 accounts"

    # SSH authorized_keys — report all, flag keys in /tmp or unusual paths
    hdr "SSH AUTHORIZED KEYS"
    key_hit=0
    while IFS=: read -r user _ _ _ _ homedir _; do
        ak="$homedir/.ssh/authorized_keys"
        [[ -f "$ak" ]] || continue
        count=$(grep -cvE '^\s*(#|$)' "$ak" 2>/dev/null || echo 0)
        [[ "$count" -eq 0 ]] && continue
        warn "$user — $count key(s) in $ak:"
        grep -vE '^\s*(#|$)' "$ak" | awk '{printf "         [%s]  %s\n", $1, $3}'
    done < /etc/passwd

    # Dangerous sshd_config settings
    hdr "SSHD CONFIG"
    for setting in "PermitRootLogin yes" "PermitEmptyPasswords yes" "GatewayPorts yes"; do
        grep -qiE "^\s*${setting}" /etc/ssh/sshd_config 2>/dev/null \
            && hit "sshd_config: $setting"
    done

    akf=$(grep -iE '^\s*AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null \
          | grep -v '\.ssh/authorized_keys')
    [[ -n "$akf" ]] && hit "Non-standard AuthorizedKeysFile: $akf"

    ok "sshd_config checked"
}

# ============================================================
# SERVICES — systemd units + cron jobs
# ============================================================
check_services() {
    hdr "SYSTEMD SERVICES"
    svc_hit=0

    SUSPICIOUS_EXEC='(/tmp/|/dev/shm/|/var/tmp/|exec.*>&|/dev/tcp|socat|mkfifo)'

    # Scan all service unit files for red-flag ExecStart lines
    while IFS= read -r svc; do
        line=$(grep -iE "^\s*ExecStart\s*=.*$SUSPICIOUS_EXEC" "$svc" 2>/dev/null)
        [[ -z "$line" ]] && continue
        hit "Suspicious systemd unit: $svc"
        echo "$line" | sed 's/^/         /'
        svc_hit=1
    done < <(find /etc/systemd /usr/lib/systemd /lib/systemd -name "*.service" 2>/dev/null)

    # Enabled non-standard services — list for review, flag unknowns
    warn "Enabled services (review for anything unexpected):"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null \
        | grep -vE '(UNIT|listed|systemd|dbus|ssh|cron|rsyslog|network|getty|cloud|snap|ufw|fail2ban|auditd)' \
        | awk '{print "         "$1}'

    [[ $svc_hit -eq 0 ]] && ok "No suspicious ExecStart commands in service units"

    # Cron — only flag entries pointing to staging dirs or classic shell escapes
    hdr "CRON JOBS"
    cron_hit=0
    SUSPICIOUS_CRON='(/tmp/|/dev/shm/|/var/tmp/|base64\s+-d|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|exec\s+.*>&)'

    for f in /etc/crontab \
              $(find /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                     /etc/cron.weekly /etc/cron.monthly -maxdepth 1 -type f 2>/dev/null); do
        [[ -f "$f" ]] || continue
        active=$(grep -vE '^\s*(#|$)' "$f" 2>/dev/null)
        [[ -z "$active" ]] && continue
        if echo "$active" | grep -qE "$SUSPICIOUS_CRON"; then
            hit "Suspicious cron in $f:"
            echo "$active" | grep -E "$SUSPICIOUS_CRON" | sed 's/^/         /'
            cron_hit=1
        else
            warn "Active cron ($f):"
            echo "$active" | sed 's/^/         /'
        fi
    done

    for u in $(cut -d: -f1 /etc/passwd); do
        ctab=$(crontab -u "$u" -l 2>/dev/null | grep -vE '^\s*(#|$)')
        [[ -z "$ctab" ]] && continue
        if echo "$ctab" | grep -qE "$SUSPICIOUS_CRON"; then
            hit "Suspicious crontab for $u:"
            echo "$ctab" | grep -E "$SUSPICIOUS_CRON" | sed 's/^/         /'
            cron_hit=1
        else
            warn "Crontab for $u:"
            echo "$ctab" | sed 's/^/         /'
        fi
    done

    [[ $cron_hit -eq 0 ]] && ok "No obviously malicious cron entries"
}

# ── run selected checks ──────────────────────────────────────
[[ $RUN_NET -eq 1 ]] && check_network
[[ $RUN_BIN -eq 1 ]] && check_binaries
[[ $RUN_USR -eq 1 ]] && check_users
[[ $RUN_SVC -eq 1 ]] && check_services

# ── summary ──────────────────────────────────────────────────
mapfile -t ALL_FINDS < "$FIND_FILE"
rm -f "$FIND_FILE"

echo ""
echo -e "${B}${CYN}────────────────────────────────────────────────────────${R}"
if [[ ${#ALL_FINDS[@]} -eq 0 ]]; then
    echo -e "${B}${GRN}  SUMMARY — 0 findings.${R}"
else
    echo -e "${B}${RED}  SUMMARY — ${#ALL_FINDS[@]} FINDING(S)${R}"
    echo -e "${B}${CYN}────────────────────────────────────────────────────────${R}"
    for i in "${!ALL_FINDS[@]}"; do
        printf "  ${RED}${B}[%2d]${R} %s\n" "$((i+1))" "${ALL_FINDS[$i]}"
    done
fi
echo -e "${B}${CYN}────────────────────────────────────────────────────────${R}\n"
