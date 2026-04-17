#!/bin/bash
set -e

(( EUID == 0 )) || { echo "must run as root"; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NFT="$HERE/nft"

[[ -x $NFT ]] || { echo "no nft at $NFT"; exit 1; }
"$NFT" list ruleset &>/dev/null || { echo "nft not working"; exit 1; }

IU=() IT=() OU=(67 53 123) OT=(443 80 53 5432)

#SCORING_ENGINES="10.0.0.1, 10.0.0.2"

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
allow() {
    (( $# > 1 )) || return 0
    echo "        $1 dport { $(csv "${@:2}") } accept"
}

RULES=$(mktemp)
trap 'rm -f "$RULES"' EXIT

{
    echo 'flush ruleset'
    echo 'table inet fw {'
    echo '    chain input {'
    echo '        type filter hook input priority 0; policy drop;'
    echo '        iif lo accept'
    echo '        ct state established,related accept'
    echo '        ip protocol icmp accept'
#    [[ -n "${SCORING_ENGINES:-}" ]] && echo "        ip saddr != { $SCORING_ENGINES } drop"
    allow udp "${IU[@]}"
    allow tcp "${IT[@]}"
    echo '    }'
    echo '    chain forward { type filter hook forward priority 0; policy drop; }'
    echo '    chain output {'
    echo '        type filter hook output priority 0; policy drop;'
    echo '        oif lo accept'
    echo '        ct state established,related accept'
    echo '        ip protocol icmp accept'
    allow udp "${OU[@]}"
    allow tcp "${OT[@]}"
    echo '    }'
    echo '}'
} > "$RULES"

for svc in firewalld ufw nftables iptables ip6tables; do
    systemctl stop    "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

"$NFT" -f "$RULES"

chattr -i /etc/nftables.rules 2>/dev/null || true
"$NFT" list ruleset > /etc/nftables.rules
chattr +i /etc/nftables.rules

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

if [[ ! " ${IT[*]} " =~ " 22 " ]]; then
    case $(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-$ID}") in
        *debian*|*ubuntu*) ssh_units=(ssh ssh.socket) ;;
        *)                 ssh_units=(sshd sshd.socket) ;;
    esac
    for u in "${ssh_units[@]}"; do
        systemctl stop "$u" 2>/dev/null || true
        systemctl mask "$u" 2>/dev/null || true
    done
fi

systemctl stop    telnet.socket 2>/dev/null || true
systemctl disable telnet.socket 2>/dev/null || true
systemctl mask    telnet.socket 2>/dev/null || true

for b in telnet nc ncat netcat nmap socat; do
    p=$(command -v "$b" 2>/dev/null) || continue
    chmod 000 "$p" 2>/dev/null || true
done

command -v ss >/dev/null || exit 0

BAD='^(nc|ncat|netcat|socat|telnet|telnetd|ssh|sshd|bash|sh|dash|zsh|ksh|python|python2|python3|perl|ruby|php|lua|node|powershell|pwsh)$'
R=$'\033[1;31m'; N=$'\033[0m'
n=0

printf '\nactive suspicious sockets:\n'
printf '%-6s %-8s %-22s %-22s %s\n' PID USER LOCAL PEER CMD

while read -r _ _ lo peer proc; do
    [[ -z $proc ]] && continue
    name=${proc#*users:((\"}; name=${name%%\"*}
    pid=${proc##*pid=};      pid=${pid%%,*}; pid=${pid%%)*}
    [[ $name =~ $BAD ]] || continue
    cmd=$(ps -o args= -p "$pid" 2>/dev/null | cut -c1-50)
    user=$(ps -o user= -p "$pid" 2>/dev/null)
    printf "${R}%-6s${N} %-8s %-22s %-22s %s\n" "${pid:--}" "${user:--}" "$lo" "${peer:--}" "${cmd:--}"
    n=$((n+1))
done < <(ss -Htnp state established state listening 2>/dev/null)

if (( n )); then
    printf '\n%d socket(s) - kill with: kill -9 <pid>\n' "$n"
else
    echo "  none"
fi
