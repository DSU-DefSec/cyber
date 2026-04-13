#!/bin/bash
# =============================================================================
# backup.sh - Service backup script for cyber competitions
# Usage:  sudo ./backup.sh [service ...] [destination]
# Example: sudo ./backup.sh apache2 ssh postgres /mnt/usb/backups
#
# Supported services:
#   apache2   (also: apache, httpd)
#   nginx
#   ssh       (also: openssh)
#   vsftpd    (also: ftp)
#   smb       (also: samba)
#   dns       (also: bind, named)
#   postgres  (also: postgresql, pg)
# =============================================================================
 
# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
 
# --- Must run as root ---
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] This script must be run as root (sudo ./backup.sh ...)${NC}"
    exit 1
fi
 
# --- Need at least: one service + one destination ---
if [[ $# -lt 2 ]]; then
    echo -e "${YELLOW}Usage: $0 [service1 service2 ...] [destination]${NC}"
    echo -e "  Services: apache2, nginx, ssh, vsftpd, smb, dns, postgres"
    exit 1
fi
 
# Last argument is the destination
DEST="${@: -1}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="${DEST}/backup_${TIMESTAMP}"
 
mkdir -p "$BACKUP_DIR" || {
    echo -e "${RED}[!] Failed to create backup directory: $BACKUP_DIR${NC}"
    exit 1
}
 
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Backup started: $(date)${NC}"
echo -e "${CYAN} Destination:    $BACKUP_DIR${NC}"
echo -e "${CYAN}============================================${NC}\n"
 
# Keep a manifest of what was backed up
MANIFEST="$BACKUP_DIR/MANIFEST.txt"
echo "Backup started: $(date)" > "$MANIFEST"
echo "Host: $(hostname)" >> "$MANIFEST"
echo "User: $(whoami)" >> "$MANIFEST"
echo "" >> "$MANIFEST"
 
# =============================================================================
# Helper: safely copy a directory
# =============================================================================
safe_copy_dir() {
    local label="$1"
    local src="$2"
    local dest="$3"
    if [[ -d "$src" ]]; then
        cp -rp "$src" "$dest" 2>/dev/null \
            && echo -e "  ${GREEN}[+]${NC} $src" \
            || echo -e "  ${RED}[-] Failed to copy:${NC} $src"
        echo "  DIR: $src -> $dest" >> "$MANIFEST"
    else
        echo -e "  ${YELLOW}[~] Not found (skipping):${NC} $src"
    fi
}
 
# =============================================================================
# Helper: safely copy a single file
# =============================================================================
safe_copy_file() {
    local src="$1"
    local dest="$2"
    if [[ -f "$src" ]]; then
        cp -p "$src" "$dest" 2>/dev/null \
            && echo -e "  ${GREEN}[+]${NC} $src" \
            || echo -e "  ${RED}[-] Failed to copy:${NC} $src"
        echo "  FILE: $src -> $dest" >> "$MANIFEST"
    else
        echo -e "  ${YELLOW}[~] Not found (skipping):${NC} $src"
    fi
}
 
# =============================================================================
# APACHE2 / HTTPD
# =============================================================================
backup_apache2() {
    echo -e "${YELLOW}[*] Backing up Apache2...${NC}"
    local D="$BACKUP_DIR/apache2"
    mkdir -p "$D"
 
    # Config (Debian/Ubuntu style)
    safe_copy_dir  "apache2" /etc/apache2           "$D/etc_apache2"
    # Config (RHEL/CentOS style)
    safe_copy_dir  "apache2" /etc/httpd             "$D/etc_httpd"
 
    # Web root
    safe_copy_dir  "apache2" /var/www               "$D/var_www"
 
    # Logs
    safe_copy_dir  "apache2" /var/log/apache2       "$D/log_apache2"
    safe_copy_dir  "apache2" /var/log/httpd         "$D/log_httpd"
 
    # systemd unit files (useful for restoring service behavior)
    safe_copy_file /lib/systemd/system/apache2.service      "$D/apache2.service"
    safe_copy_file /usr/lib/systemd/system/httpd.service    "$D/httpd.service"
 
    echo -e "${GREEN}[+] Apache2 done${NC}\n"
    echo "apache2: complete" >> "$MANIFEST"
}
 
# =============================================================================
# NGINX
# =============================================================================
backup_nginx() {
    echo -e "${YELLOW}[*] Backing up Nginx...${NC}"
    local D="$BACKUP_DIR/nginx"
    mkdir -p "$D"
 
    # Config
    safe_copy_dir  "nginx" /etc/nginx               "$D/etc_nginx"
 
    # Web roots
    safe_copy_dir  "nginx" /var/www                 "$D/var_www"
    safe_copy_dir  "nginx" /usr/share/nginx/html    "$D/html"
 
    # Logs
    safe_copy_dir  "nginx" /var/log/nginx           "$D/log_nginx"
 
    # systemd unit
    safe_copy_file /lib/systemd/system/nginx.service "$D/nginx.service"
 
    echo -e "${GREEN}[+] Nginx done${NC}\n"
    echo "nginx: complete" >> "$MANIFEST"
}
 
# =============================================================================
# OPENSSH
# =============================================================================
backup_ssh() {
    echo -e "${YELLOW}[*] Backing up OpenSSH...${NC}"
    local D="$BACKUP_DIR/openssh"
    mkdir -p "$D"
 
    # Config + host keys (THIS is what you want — attacker can swap host keys)
    safe_copy_dir  "ssh" /etc/ssh                   "$D/etc_ssh"
 
    # PAM SSH config
    safe_copy_file /etc/pam.d/sshd                  "$D/pam_sshd"
 
    # Per-user .ssh directories (authorized_keys, known_hosts, etc.)
    local USER_SSH_DIR="$D/user_ssh_dirs"
    mkdir -p "$USER_SSH_DIR"
    for HOME_DIR in /root /home/*; do
        if [[ -d "$HOME_DIR/.ssh" ]]; then
            USER=$(basename "$HOME_DIR")
            cp -rp "$HOME_DIR/.ssh" "$USER_SSH_DIR/${USER}_ssh" 2>/dev/null \
                && echo -e "  ${GREEN}[+]${NC} $HOME_DIR/.ssh" \
                || echo -e "  ${RED}[-] Failed:${NC} $HOME_DIR/.ssh"
        fi
    done
 
    # systemd unit
    safe_copy_file /lib/systemd/system/ssh.service          "$D/ssh.service"
    safe_copy_file /usr/lib/systemd/system/sshd.service     "$D/sshd.service"
 
    echo -e "${GREEN}[+] OpenSSH done${NC}\n"
    echo "ssh: complete" >> "$MANIFEST"
}
 
# =============================================================================
# VSFTPD
# =============================================================================
backup_vsftpd() {
    echo -e "${YELLOW}[*] Backing up vsftpd...${NC}"
    local D="$BACKUP_DIR/vsftpd"
    mkdir -p "$D"
 
    # Config
    safe_copy_file /etc/vsftpd.conf                 "$D/vsftpd.conf"
    safe_copy_dir  "vsftpd" /etc/vsftpd             "$D/etc_vsftpd"
 
    # User whitelists / blacklists
    safe_copy_file /etc/vsftpd.userlist             "$D/vsftpd.userlist"
    safe_copy_file /etc/ftpusers                    "$D/ftpusers"
    safe_copy_file /etc/vsftpd.chroot_list          "$D/vsftpd.chroot_list"
 
    # FTP data (try common locations)
    safe_copy_dir  "vsftpd" /srv/ftp                "$D/srv_ftp"
    safe_copy_dir  "vsftpd" /var/ftp                "$D/var_ftp"
    safe_copy_dir  "vsftpd" /home/ftp               "$D/home_ftp"
 
    # PAM config
    safe_copy_file /etc/pam.d/vsftpd                "$D/pam_vsftpd"
 
    # systemd unit
    safe_copy_file /lib/systemd/system/vsftpd.service "$D/vsftpd.service"
 
    echo -e "${GREEN}[+] vsftpd done${NC}\n"
    echo "vsftpd: complete" >> "$MANIFEST"
}
 
# =============================================================================
# SAMBA / SMB
# =============================================================================
backup_smb() {
    echo -e "${YELLOW}[*] Backing up Samba (SMB)...${NC}"
    local D="$BACKUP_DIR/samba"
    mkdir -p "$D"
 
    # Config
    safe_copy_dir  "samba" /etc/samba               "$D/etc_samba"
 
    # Samba TDB databases (user accounts, secrets, etc.)
    safe_copy_dir  "samba" /var/lib/samba           "$D/var_lib_samba"
 
    # Common share locations
    safe_copy_dir  "samba" /srv/samba               "$D/srv_samba"
    safe_copy_dir  "samba" /srv/shares              "$D/srv_shares"
    safe_copy_dir  "samba" /home/shares             "$D/home_shares"
 
    # Logs
    safe_copy_dir  "samba" /var/log/samba           "$D/log_samba"
 
    # systemd units
    safe_copy_file /lib/systemd/system/smbd.service "$D/smbd.service"
    safe_copy_file /lib/systemd/system/nmbd.service "$D/nmbd.service"
 
    echo -e "${GREEN}[+] Samba done${NC}\n"
    echo "samba: complete" >> "$MANIFEST"
}
 
# =============================================================================
# BIND DNS
# =============================================================================
backup_dns() {
    echo -e "${YELLOW}[*] Backing up BIND DNS...${NC}"
    local D="$BACKUP_DIR/bind_dns"
    mkdir -p "$D"
 
    # Config - Debian/Ubuntu
    safe_copy_dir  "dns" /etc/bind                  "$D/etc_bind"
 
    # Config - RHEL/CentOS
    safe_copy_file /etc/named.conf                  "$D/named.conf"
    safe_copy_dir  "dns" /etc/named                 "$D/etc_named"
 
    # Zone files (Debian)
    safe_copy_dir  "dns" /var/lib/bind              "$D/var_lib_bind"
    safe_copy_dir  "dns" /var/cache/bind            "$D/var_cache_bind"
 
    # Zone files (RHEL)
    safe_copy_dir  "dns" /var/named                 "$D/var_named"
 
    # Logs
    safe_copy_dir  "dns" /var/log/named             "$D/log_named"
 
    # systemd units
    safe_copy_file /lib/systemd/system/bind9.service   "$D/bind9.service"
    safe_copy_file /usr/lib/systemd/system/named.service "$D/named.service"
 
    echo -e "${GREEN}[+] BIND DNS done${NC}\n"
    echo "dns: complete" >> "$MANIFEST"
}
 
# =============================================================================
# POSTGRESQL
# =============================================================================
backup_postgres() {
    echo -e "${YELLOW}[*] Backing up PostgreSQL...${NC}"
    local D="$BACKUP_DIR/postgres"
    mkdir -p "$D"
 
    # Config
    safe_copy_dir  "postgres" /etc/postgresql       "$D/etc_postgresql"
 
    # Data directory (includes pg_hba.conf, pg_ident.conf, postgresql.conf)
    safe_copy_dir  "postgres" /var/lib/postgresql   "$D/var_lib_postgresql"
 
    # SQL dump of all databases (most portable backup format)
    if id "postgres" &>/dev/null; then
        echo -e "  ${YELLOW}[*] Running pg_dumpall (full SQL dump)...${NC}"
        sudo -u postgres pg_dumpall > "$D/pg_dumpall_${TIMESTAMP}.sql" 2>/dev/null \
            && echo -e "  ${GREEN}[+] pg_dumpall successful${NC}" \
            || echo -e "  ${RED}[-] pg_dumpall failed — is the service running?${NC}"
 
        # Also dump each database individually for easier restore
        echo -e "  ${YELLOW}[*] Dumping individual databases...${NC}"
        local DB_DIR="$D/individual_dbs"
        mkdir -p "$DB_DIR"
        sudo -u postgres psql -tAc "SELECT datname FROM pg_database WHERE datistemplate = false;" 2>/dev/null | \
        while read -r DBNAME; do
            sudo -u postgres pg_dump "$DBNAME" > "$DB_DIR/${DBNAME}_${TIMESTAMP}.sql" 2>/dev/null \
                && echo -e "  ${GREEN}[+] Dumped:${NC} $DBNAME" \
                || echo -e "  ${RED}[-] Failed:${NC} $DBNAME"
        done
    else
        echo -e "  ${YELLOW}[~] 'postgres' system user not found — skipping pg_dump${NC}"
    fi
 
    # Logs
    safe_copy_dir  "postgres" /var/log/postgresql   "$D/log_postgresql"
 
    # systemd unit
    safe_copy_file /lib/systemd/system/postgresql.service "$D/postgresql.service"
 
    echo -e "${GREEN}[+] PostgreSQL done${NC}\n"
    echo "postgres: complete" >> "$MANIFEST"
}
 
# =============================================================================
# MAIN LOOP — iterate all args except the last (destination)
# =============================================================================
for ARG in "${@:1:$# - 1}"; do
    case "$ARG" in
        apache2|apache|httpd)   backup_apache2  ;;
        nginx)                  backup_nginx    ;;
        ssh|openssh)            backup_ssh      ;;
        vsftpd|ftp)             backup_vsftpd   ;;
        smb|samba)              backup_smb      ;;
        dns|bind|named)         backup_dns      ;;
        postgres|postgresql|pg) backup_postgres ;;
        *)
            echo -e "${RED}[!] Unknown service: '$ARG' — skipping${NC}"
            echo -e "    Available: apache2, nginx, ssh, vsftpd, smb, dns, postgres"
            ;;
    esac
done
 
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Backup complete: $(date)${NC}"
echo -e "${CYAN} Files saved to: $BACKUP_DIR${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}Tip: verify with:${NC}  ls -lR $BACKUP_DIR"
 
echo "" >> "$MANIFEST"
echo "Backup finished: $(date)" >> "$MANIFEST"