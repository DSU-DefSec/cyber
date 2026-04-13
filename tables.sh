#!/bin/bash
# firewall deploy + remote access lockdown
set -e

(( EUID == 0 )) || { echo "must run as root"; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NFT="$HERE/nft"

[[ -x $NFT ]] || { echo "no nft binary at $NFT"; exit 1; }
"$NFT" list ruleset &>/dev/null || { echo "nft broken (nf_tables kernel support?)"; exit 1; }

IU=() IT=() OU=() OT=()
while (( $# )); do
    case $1 in
        -IU) shift; while (( $# )) && [[ $1 != -* ]]; do IU+=("$1"); shift; done ;;
        -IT) shift; while (( $# )) && [[ $1 != -* ]]; do IT+=("$1"); shift; done ;;
        -OU) shift; while (( $# )) && [[ $1 != -* ]]; do OU+=("$1"); shift; done ;;
        -OT) shift; while (( $# )) && [[ $1 != -* ]]; do OT+=("$1"); shift; done ;;
        *) echo "bad flag: $1"; exit 1 ;;
    esac
done

csv() { local IFS=,; echo "$*"; }
allow() { (( $# > 2 )) && echo "        $1 dport { $(csv "${@:3}") } accept"; }

RULES=$(mktemp); trap 'rm -f "$RULES"' EXIT
{
    echo 'flush ruleset'
    echo 'table inet fw {'
    echo '    chain input {'
    echo '        type filter hook input priority 0; policy drop;'
    echo '        iif lo accept'
    echo '        ct state established,related accept'
    allow udp in "${IU[@]}"
    allow tcp in "${IT[@]}"
    echo '    }'
    echo '    chain forward { type filter hook forward priority 0; policy drop; }'
    echo '    chain output {'
    echo '        type filter hook output priority 0; policy drop;'
    echo '        oif lo accept'
    echo '        ct state established,related accept'
    allow udp out "${OU[@]}"
    allow tcp out "${OT[@]}"
    echo '    }'
    echo '}'
} > "$RULES"

"$NFT" -f "$RULES"

# persist + lock
chattr -i /etc/nftables.rules 2>/dev/null || true
"$NFT" list ruleset > /etc/nftables.rules
chattr +i /etc/nftables.rules

# reload on boot
install -m 755 "$NFT" /usr/local/sbin/nft-static
cat >/etc/systemd/system/fw-static.service <<EOF
[Unit]
Description=static nftables loader
Before=network-pre.target
Wants=network-pre.target
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/nft-static -f /etc/nftables.rules
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload || true
systemctl enable fw-static.service &>/dev/null || true

# kill sshd if ssh isn't scored
if [[ ! " ${IT[*]} " =~ " 22 " ]]; then
    systemctl stop sshd 2>/dev/null || true
    systemctl disable sshd 2>/dev/null || true
    systemctl mask sshd 2>/dev/null || true
    sshd_bin=$(command -v sshd || true)
    [[ -n $sshd_bin ]] && { chmod 000 "$sshd_bin"; chattr +i "$sshd_bin"; }
    chattr +i /etc/ssh/sshd_config 2>/dev/null || true
fi

# telnet
systemctl stop telnet.socket 2>/dev/null || true
systemctl disable telnet.socket 2>/dev/null || true
systemctl mask telnet.socket 2>/dev/null || true

# nuke the usual RAT toolkit
for b in telnet nc ncat netcat nmap socat; do
    p=$(command -v "$b" 2>/dev/null) || continue
    chmod 000 "$p" 2>/dev/null || true
    chattr +i "$p" 2>/dev/null || true
done

# active connection audit — any shell/remote-access tool still holding
# a socket is almost certainly not ours
command -v ss >/dev/null || exit 0

BAD='^(nc|ncat|netcat|socat|telnet|telnetd|ssh|sshd|bash|sh|dash|zsh|ksh|python|python2|python3|perl|ruby|php|lua|node|powershell|pwsh)$'
R=$'\033[1;31m'; N=$'\033[0m'
n=0

printf '\nactive suspicious sockets:\n'
printf '%-6s %-8s %-22s %-22s %s\n' PID USER LOCAL PEER CMD

while read -r _ _ lo peer proc; do
    [[ -z $proc ]] && continue
    name=${proc#*users:((\"}; name=${name%%\"*}
    pid=${proc##*pid=}; pid=${pid%%,*}; pid=${pid%%)*}
    [[ $name =~ $BAD ]] || continue
    cmd=$(ps -o args= -p "$pid" 2>/dev/null | cut -c1-50)
    user=$(ps -o user= -p "$pid" 2>/dev/null)
    printf "${R}%-6s${N} %-8s %-22s %-22s %s\n" "${pid:--}" "${user:--}" "$lo" "${peer:--}" "${cmd:--}"
    n=$((n+1))
done < <(ss -Htnp state established state listening 2>/dev/null)

(( n )) && printf '\n%d socket(s) — kill with: kill -9 <pid>\n' "$n" || echo "  none"
