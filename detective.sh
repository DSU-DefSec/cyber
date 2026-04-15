#!/bin/bash
# find backdoors on systems

RED=$'\033[0;31m'; YEL=$'\033[1;33m'; GRN=$'\033[0;32m'
CYN=$'\033[0;36m'; B=$'\033[1m'; R=$'\033[0m'

FINDS=$(mktemp); trap 'rm -f "$FINDS"' EXIT
hit()  { echo "${RED}${B}[!!]${R} $*"; echo "$*" >>"$FINDS"; }
warn() { echo "${YEL}[??]${R} $*"; }
ok()   { echo "${GRN}[ok]${R} $*"; }
hdr()  { echo; echo "${B}${CYN}── $1 ──${R}"; }

. /etc/os-release 2>/dev/null
IS_DEB=0; IS_RPM=0
[[ $ID == ubuntu ]] && IS_DEB=1
[[ $ID == rocky || $ID_LIKE == *rhel* ]] && IS_RPM=1

echo "${B}${CYN} detective │ $(hostname) │ ${PRETTY_NAME:-$ID} │ $(date '+%H:%M %b %d')${R}"

# check for network listeners
hdr "NETWORK LISTENERS:"

if command -v ss &>/dev/null; then
    LISTEN=$(ss -tlnp 2>/dev/null | tail -n +2)
    ESTAB=$(ss -tnp 2>/dev/null | grep -i estab)
else
    LISTEN=$(netstat -tlnp 2>/dev/null | tail -n +3)
    ESTAB=$(netstat -tnp 2>/dev/null | grep -i estab)
fi

net_hit=0
while IFS= read -r line; do
    [[ -z $line ]] && continue
    port=$(echo "$line" | grep -oP '(?<=[:\]])(\d+)(?=\s)' | tail -1)
    [[ -z $port ]] && continue
    echo "$EXPECTED" | grep -wq "$port" && continue
    pid=$(echo "$line" | grep -oP 'pid=\K\d+')
    bin=$([[ -n $pid ]] && readlink /proc/"$pid"/exe 2>/dev/null || echo unknown)
    hit "listener :$port → $bin"
    net_hit=1
done <<< "$LISTEN"
(( net_hit == 0 )) && ok "no unexpected listening ports"

if [[ -n $ESTAB ]]; then
    warn "established connections (review):"
    echo "$ESTAB" | awk '{printf "       %s  %s\n", $5, $NF}'
fi

# look for hidden open ports 
PROC_PORTS=$(awk 'NR>1 && $4=="0A" {printf "%d\n", strtonum("0x" substr($2, index($2,":")+1))}' \
    /proc/net/tcp /proc/net/tcp6 2>/dev/null | sort -nu)
SS_PORTS=$(echo "$LISTEN" | grep -oP '(?<=[:\]])\d+(?=\s)' | sort -nu)
for p in $PROC_PORTS; do
    echo "$SS_PORTS" | grep -qw "$p" || hit "port $p in /proc/net/tcp but NOT in ss — rootkit?"
done

# firewall redirection / hijacking
if command -v nft &>/dev/null; then
    nft list ruleset 2>/dev/null | grep -iE 'dnat|redirect' | while read -r l; do
        hit "nftables NAT rule: $l"
    done
fi
for ipt in iptables iptables-legacy; do
    command -v $ipt &>/dev/null || continue
    $ipt -t nat -S 2>/dev/null | grep -iE 'DNAT|REDIRECT' | while read -r l; do
        hit "$ipt NAT rule: $l"
    done
done

# tampered entries in local cache
grep -vE '^\s*(#|$)' /etc/hosts 2>/dev/null | \
    grep -vE '^\s*(127\.|::1|ff02::|fe00::|255\.255\.255\.255)' | while read -r l; do
    warn "non-loopback /etc/hosts: $l"
done

# check for backdoored binaries
hdr "BINARY INTEGRITY"

if (( IS_DEB )); then
    if command -v debsums &>/dev/null; then
        debsums -c 2>/dev/null | grep -E '/(s?bin|lib|lib64)/' | \
            while read -r l; do hit "debsums: $l"; done
    else
        warn "debsums missing — using dpkg -V (binaries only)"
        # Only md5 mismatches (pos 3 == 5), non-conffiles, under bin/lib paths.
        # check only for backdoored binaries, not missing ones
        dpkg -V 2>/dev/null | awk '$1 ~ /^..5/ && $2 != "c" {print}' | \
            grep -E '/(s?bin|lib|lib64)/' | \
            while read -r l; do hit "dpkg -V: $l"; done
    fi
elif (( IS_RPM )); then
    # Only md5/size/mode changes on non-config file binaries/libs.
    rpm -Va 2>/dev/null | awk '$1 ~ /^.{0,8}[5SM]/ && $2 != "c" {print}' | \
        grep -E '/(s?bin|lib|lib64)/' | \
        while read -r l; do hit "rpm -Va: $l"; done
fi

# nologin/false backdoored to shell
for bin in /sbin/nologin /usr/sbin/nologin /bin/false /usr/bin/false; do
    [[ -f $bin ]] || continue
    strings "$bin" 2>/dev/null | grep -qiE '(/bin/sh|/bin/bash|/dev/tcp|socat|nc -e|bash -i)' \
        && hit "$bin contains shell strings — backdoor"
    [[ $bin == *nologin ]] && ! strings "$bin" 2>/dev/null | grep -qiE '(not available|not allowed|account)' \
        && hit "$bin missing denial strings — possible shell swap"
done
grep -qE '^/(s?bin|usr/(s?bin)?)/(nologin|false)$' /etc/shells 2>/dev/null \
    && hit "/etc/shells lists nologin/false"

# ELF in staging
while IFS= read -r f; do
    file "$f" 2>/dev/null | grep -q ELF && hit "ELF in staging: $f"
done < <(find /tmp /dev/shm /var/tmp -type f 2>/dev/null)

# check for ghost binaries
for pid in /proc/[0-9]*/exe; do
    readlink "$pid" 2>/dev/null | grep -q '(deleted)' || continue
    n=${pid#/proc/}; n=${n%/exe}
    hit "PID $n from DELETED binary: $(ps -p "$n" -o cmd= 2>/dev/null)"
done

# Preload hooks — LKM/library injection
[[ -f /etc/ld.so.preload ]] && hit "/etc/ld.so.preload: $(cat /etc/ld.so.preload)"
for f in /etc/ld.so.conf.d/*.conf; do
    [[ -f $f ]] || continue
    grep -vE '^\s*(#|$)' "$f" 2>/dev/null | grep -E '^/(tmp|dev/shm|var/tmp|home)' \
        && hit "suspect ld.so path in $f"
done
[[ -n $LD_PRELOAD ]] && hit "LD_PRELOAD set in env: $LD_PRELOAD"

# Recently modified system binaries
find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 2>/dev/null | while read -r f; do
    warn "recently modified: $f ($(stat -c %y "$f" 2>/dev/null | cut -d. -f1))"
done

# nonstandard suid binarues
KNOWN_SUID='/usr/bin/(passwd|sudo|su|chsh|chfn|gpasswd|newgrp|mount|umount|pkexec|crontab|at|ssh-agent|fusermount.?)$|/usr/lib/(openssh/ssh-keysign|dbus-1.0/dbus-daemon-launch-helper|polkit-1/polkit-agent-helper-1|snapd/snap-confine|eject/dmcrypt-get-device)|/usr/(libexec|sbin)/(pt_chown|unix_chkpwd|mount\.nfs)|/sbin/(mount\.nfs|unix_chkpwd)|/bin/(su|mount|umount|ping|fusermount)'
find /usr/bin/ -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
    echo "$f" | grep -qE "$KNOWN_SUID" || hit "unusual SUID: $f"
done

find /home -xdev -perm -4000 -type f 2>/dev/null | while read -r f; do
    echo "$f" | grep -qE "$KNOWN_SUID" || hit "unusual SUID: $f"
done

# Elevated capabilities
if command -v getcap &>/dev/null; then
    getcap -r / 2>/dev/null | grep -vE '(cap_net_bind_service|cap_net_raw)\+(ep|eip)$' | while read -r l; do
        [[ -n $l ]] && hit "capability: $l"
    done
fi

# Immutable files (attacker pinning config)
if command -v lsattr &>/dev/null; then
    lsattr /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config 2>/dev/null | \
        grep -E '^\S*i\S*\s' | while read -r l; do hit "immutable: $l"; done
fi

# audit openssh 
hdr "USERS & SSH"

awk -F: '($3==0 && $1!="root"){print}' /etc/passwd | while read -r l; do
    hit "extra UID 0: $l"
done

awk -F: '($6 ~ /^\/tmp|^\/dev|^\/var\/tmp/){print}' /etc/passwd | while read -r l; do
    hit "suspicious home: $l"
done

# system accounts with shells
awk -F: '($2 !~ /^[!*]/ && $2 != "") {print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    uid=$(id -u "$u" 2>/dev/null)
    [[ -z $uid || $uid -ge 1000 || $u == root ]] && continue
    hit "system account with password: $u"
done

while IFS=: read -r user _ uid _ _ _ shell; do
    [[ $uid -lt 1000 && $uid -ne 0 ]] && continue
    [[ $shell =~ (nologin|false|sync|halt|shutdown) || -z $shell ]] && continue
    warn "interactive account: $user (uid=$uid shell=$shell)"
done < /etc/passwd

while IFS=: read -r user _ _ _ _ homedir _; do
    ak="$homedir/.ssh/authorized_keys"
    [[ -f $ak ]] || continue
    count=$(grep -cvE '^\s*(#|$)' "$ak" 2>/dev/null || echo 0)
    (( count )) || continue
    warn "$user — $count SSH key(s) in $ak:"
    grep -vE '^\s*(#|$)' "$ak" | awk '{printf "       [%s] %s\n", $1, $3}'
done < /etc/passwd

for s in "PermitRootLogin yes" "PermitEmptyPasswords yes" "GatewayPorts yes"; do
    grep -qiE "^\s*${s}" /etc/ssh/sshd_config 2>/dev/null && hit "sshd_config: $s"
done
akf=$(grep -iE '^\s*AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null | grep -v '\.ssh/authorized_keys')
[[ -n $akf ]] && hit "non-standard AuthorizedKeysFile: $akf"

grep -rhsiE 'NOPASSWD.*ALL|ALL.*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null \
    | grep -v '^\s*#' | while read -r l; do hit "sudoers NOPASSWD ALL: $l"; done

# PAM pam_exec — command execution on auth
grep -rhE '^\s*[^#].*pam_exec\.so' /etc/pam.d/ 2>/dev/null | while read -r l; do
    hit "PAM pam_exec: $l"
done

# check for common persistence tactics
hdr "PERSISTENCE"

SUSPECT='(/tmp/|/dev/shm/|/var/tmp/|/dev/tcp|socat|mkfifo|base64\s+-d|wget.*\|.*sh|curl.*\|.*sh|bash\s+-i|nc\s+-e|python.*-c.*socket|perl.*-e.*socket)'

while IFS= read -r svc; do
    line=$(grep -iE "^\s*ExecStart\s*=.*$SUSPECT" "$svc" 2>/dev/null) || continue
    [[ -z $line ]] && continue
    hit "systemd unit: $svc"
    echo "$line" | sed 's/^/       /'
done < <(find /etc/systemd /usr/lib/systemd /lib/systemd -name "*.service" 2>/dev/null)

# systemd timers
while IFS= read -r t; do
    warn "systemd timer: $(basename "$t")"
done < <(find /etc/systemd /usr/lib/systemd -name "*.timer" 2>/dev/null | head -20)

for f in /etc/crontab /etc/rc.local $(find /etc/cron.d /etc/cron.daily /etc/cron.hourly \
        /etc/cron.weekly /etc/cron.monthly /etc/profile.d -maxdepth 1 -type f 2>/dev/null); do
    [[ -f $f ]] || continue
    active=$(grep -vE '^\s*(#|$)' "$f" 2>/dev/null)
    [[ -z $active ]] && continue
    if echo "$active" | grep -qE "$SUSPECT"; then
        hit "suspicious $f:"
        echo "$active" | grep -E "$SUSPECT" | sed 's/^/       /'
    fi
done

for u in $(cut -d: -f1 /etc/passwd); do
    ctab=$(crontab -u "$u" -l 2>/dev/null | grep -vE '^\s*(#|$)')
    [[ -z $ctab ]] && continue
    if echo "$ctab" | grep -qE "$SUSPECT"; then
        hit "suspicious crontab $u:"
        echo "$ctab" | grep -E "$SUSPECT" | sed 's/^/       /'
    else
        warn "$u crontab: $(echo "$ctab" | head -3 | tr '\n' ';')"
    fi
done

# at jobs
command -v atq &>/dev/null && atq 2>/dev/null | while read -r l; do
    [[ -n $l ]] && warn "at job: $l"
done

# Kernel modules from unusual paths
lsmod 2>/dev/null | awk 'NR>1 {print $1}' | while read -r m; do
    path=$(modinfo -n "$m" 2>/dev/null)
    [[ -z $path ]] && continue
    [[ $path == /lib/modules/* || $path == /usr/lib/modules/* ]] && continue
    hit "kmod from unusual path: $m → $path"
done

# print a summary of the findings
echo
mapfile -t ALL < "$FINDS"
if (( ${#ALL[@]} == 0 )); then
    echo "${B}${GRN}SUMMARY — 0 findings${R}"
else
    echo "${B}${RED}SUMMARY — ${#ALL[@]} finding(s)${R}"
    for i in "${!ALL[@]}"; do printf "  ${RED}${B}[%2d]${R} %s\n" "$((i+1))" "${ALL[$i]}"; done
fi
echo
