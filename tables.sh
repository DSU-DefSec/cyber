#!/bin/bash
# deploys the firewall and locks down remote access

# fail if iptables not working
if ! command -v iptables &>/dev/null || ! iptables -L &>/dev/null; then
    echo "iptables not found or not working, exiting"
    exit 1
fi

# Initialize arrays for each direction/protocol
INPUT_UDP=()
INPUT_TCP=()
OUTPUT_UDP=()
OUTPUT_TCP=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -IU) shift
             while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                 INPUT_UDP+=("$1"); shift
             done ;;
        -IT) shift
             while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                 INPUT_TCP+=("$1"); shift
             done ;;
        -OU) shift
             while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                 OUTPUT_UDP+=("$1"); shift
             done ;;
        -OT) shift
             while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                 OUTPUT_TCP+=("$1"); shift
             done ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Flush existing rules
iptables -F
iptables -X

# Default policy: drop everything
# Kills reverse shells because we cleared all rules before
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related connections (critical — lets responses come back)
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Apply parsed rules
for port in "${INPUT_UDP[@]}"; do
    iptables -A INPUT -p udp --dport "$port" -j ACCEPT
done
for port in "${INPUT_TCP[@]}"; do
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
done
for port in "${OUTPUT_UDP[@]}"; do
    iptables -A OUTPUT -p udp --dport "$port" -j ACCEPT
done
for port in "${OUTPUT_TCP[@]}"; do
    iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT
done

# Save the rules
# Replace later if iptables-save is useable
iptables -S > /etc/iptables.rules
chattr +i /etc/iptables.rules

# This an interesting idea to prevent rules being deleted but seems suspect
#cp $(which iptables) /usr/local/sbin/.fw
#chmod 700 /usr/local/sbin/.fw
#chmod 000 $(which iptables)
#chattr +i $(which iptables)

# Shut down the ssh server if not scored (proxmox access makes this okay)
if [[ ! " ${INPUT_TCP[*]} " =~ " 22 " ]]; then
    systemctl stop sshd
    systemctl disable sshd
	systemctl mask sshd
	chmod 000 $(which sshd 2>/dev/null) 2>/dev/null
	chattr +i $(which sshd 2>/dev/null) 2>/dev/null
	chattr +i /etc/ssh/sshd_config
fi

# Get rid of sneaky telnet
systemctl stop telnet.socket 2>/dev/null
systemctl disable telnet.socket 2>/dev/null
systemctl mask telnet.socket 2>/dev/null

# Disable remote access binaries
chmod 000 $(which telnet nc ncat netcat nmap socat 2>/dev/null) 2>/dev/null
chattr +i $(which telnet nc ncat netcat nmap socat 2>/dev/null) 2>/dev/null
