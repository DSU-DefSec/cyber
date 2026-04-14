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
{
    echo "Backup started: $(date)"
    echo "Host: $(hostname)"
    echo "User: $(whoami)"
    echo "OS: $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    echo ""
} > "$MANIFEST"

# =============================================================================
# Helper: safely copy a directory
# =============================================================================
safe_copy_dir() {
    local src="$1"
    local dest="$2"
    if [[ -d "$src" ]]; then
        cp -rp "$src" "$dest" 2>/dev/null \
            && echo -e "  ${GREEN}[+]${NC} $src" \
            || echo -e "  ${RED}[-] Failed to copy:${NC} $src"
        echo "  DIR: $src -> $dest" >> "$MANIFEST"
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
    fi
}

# =============================================================================
# Helper: copy a systemd unit file from whichever standard location it lives
# (vendor dir varies across distros: /lib on Debian, /usr/lib on RHEL/Rocky).
# Drop-in overrides under /etc/systemd/system/<unit>.d/ are handled separately
# by backup_dropins.
# =============================================================================
backup_unit() {
    local unit="$1"
    local outdir="$2"
    mkdir -p "$outdir"
    for p in \
        "/lib/systemd/system/${unit}" \
        "/usr/lib/systemd/system/${unit}" \
        "/etc/systemd/system/${unit}"; do
        if [[ -f "$p" ]]; then
            cp -p "$p" "$outdir/${unit}" 2>/dev/null \
                && echo -e "  ${GREEN}[+]${NC} $p"
            echo "  UNIT: $p -> $outdir/${unit}" >> "$MANIFEST"
        fi
    done
}

# =============================================================================
# Helper: copy /etc/systemd/system/<unit>.service.d/ drop-in dirs
# =============================================================================
backup_dropins() {
    local outdir="$1"; shift
    mkdir -p "$outdir"
    for unit in "$@"; do
        local d="/etc/systemd/system/${unit}.service.d"
        if [[ -d "$d" ]]; then
            cp -rp "$d" "$outdir/${unit}.service.d" 2>/dev/null \
                && echo -e "  ${GREEN}[+]${NC} $d"
            echo "  DROPIN: $d" >> "$MANIFEST"
        fi
    done
}

# =============================================================================
# APACHE2 / HTTPD
# =============================================================================
backup_apache2() {
    echo -e "${YELLOW}[*] Backing up Apache2...${NC}"
    local D="$BACKUP_DIR/apache2"
    mkdir -p "$D"

    # Config
    safe_copy_dir  /etc/apache2         "$D/etc_apache2"       # Debian/Ubuntu
    safe_copy_dir  /etc/httpd           "$D/etc_httpd"         # RHEL/Rocky

    # Env / defaults
    safe_copy_file /etc/default/apache2 "$D/default_apache2"   # Ubuntu
    safe_copy_file /etc/sysconfig/httpd "$D/sysconfig_httpd"   # Rocky

    # Web root
    safe_copy_dir  /var/www             "$D/var_www"

    # Logs
    safe_copy_dir  /var/log/apache2     "$D/log_apache2"
    safe_copy_dir  /var/log/httpd       "$D/log_httpd"

    # TLS material commonly referenced from apache configs
    safe_copy_dir  /etc/letsencrypt     "$D/letsencrypt"
    safe_copy_dir  /etc/ssl/private     "$D/ssl_private"       # Ubuntu
    safe_copy_dir  /etc/pki/tls/private "$D/pki_tls_private"   # Rocky

    # Unit files + drop-ins
    backup_unit    apache2.service      "$D/units"
    backup_unit    httpd.service        "$D/units"
    backup_dropins "$D/dropins" apache2 httpd

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
    safe_copy_dir  /etc/nginx              "$D/etc_nginx"

    # Env / defaults
    safe_copy_file /etc/default/nginx      "$D/default_nginx"    # Ubuntu
    safe_copy_file /etc/sysconfig/nginx    "$D/sysconfig_nginx"  # Rocky

    # Web roots
    safe_copy_dir  /var/www                "$D/var_www"
    safe_copy_dir  /usr/share/nginx/html   "$D/html"

    # Logs
    safe_copy_dir  /var/log/nginx          "$D/log_nginx"

    # TLS material
    safe_copy_dir  /etc/letsencrypt        "$D/letsencrypt"
    safe_copy_dir  /etc/ssl/private        "$D/ssl_private"
    safe_copy_dir  /etc/pki/tls/private    "$D/pki_tls_private"

    # Unit files + drop-ins
    backup_unit    nginx.service           "$D/units"
    backup_dropins "$D/dropins" nginx

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
    safe_copy_dir  /etc/ssh             "$D/etc_ssh"

    # PAM SSH config
    safe_copy_file /etc/pam.d/sshd      "$D/pam_sshd"

    # Env / defaults
    safe_copy_file /etc/default/ssh     "$D/default_ssh"      # Ubuntu
    safe_copy_file /etc/sysconfig/sshd  "$D/sysconfig_sshd"   # Rocky

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

    # Unit files (service + socket on both distros) + drop-ins
    backup_unit    ssh.service       "$D/units"
    backup_unit    ssh.socket        "$D/units"
    backup_unit    sshd.service      "$D/units"
    backup_unit    sshd.socket       "$D/units"
    backup_dropins "$D/dropins" ssh ssh@ sshd sshd@

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
    safe_copy_file /etc/vsftpd.conf          "$D/vsftpd.conf"
    safe_copy_dir  /etc/vsftpd               "$D/etc_vsftpd"

    # User whitelists / blacklists
    safe_copy_file /etc/vsftpd.userlist      "$D/vsftpd.userlist"
    safe_copy_file /etc/ftpusers             "$D/ftpusers"
    safe_copy_file /etc/vsftpd.chroot_list   "$D/vsftpd.chroot_list"

    # FTP data (try common locations)
    safe_copy_dir  /srv/ftp                  "$D/srv_ftp"
    safe_copy_dir  /var/ftp                  "$D/var_ftp"
    safe_copy_dir  /home/ftp                 "$D/home_ftp"

    # PAM + env
    safe_copy_file /etc/pam.d/vsftpd         "$D/pam_vsftpd"
    safe_copy_file /etc/sysconfig/vsftpd     "$D/sysconfig_vsftpd"   # Rocky
    safe_copy_file /etc/default/vsftpd       "$D/default_vsftpd"     # Ubuntu (rare)

    # Unit file + drop-ins
    backup_unit    vsftpd.service            "$D/units"
    backup_dropins "$D/dropins" vsftpd

    echo -e "${GREEN}[+] vsftpd done${NC}\n"
    echo "vsftpd: complete" >> "$MANIFEST"
}

# =============================================================================
# SAMBA / SMB
#   Unit names: smbd/nmbd on Debian/Ubuntu, smb/nmb on RHEL/Rocky.
# =============================================================================
backup_smb() {
    echo -e "${YELLOW}[*] Backing up Samba (SMB)...${NC}"
    local D="$BACKUP_DIR/samba"
    mkdir -p "$D"

    # Config
    safe_copy_dir  /etc/samba            "$D/etc_samba"

    # Env / defaults
    safe_copy_file /etc/default/samba    "$D/default_samba"    # Ubuntu
    safe_copy_file /etc/sysconfig/samba  "$D/sysconfig_samba"  # Rocky

    # Samba TDB databases (user accounts, secrets, etc.)
    safe_copy_dir  /var/lib/samba        "$D/var_lib_samba"

    # Common share locations
    safe_copy_dir  /srv/samba            "$D/srv_samba"
    safe_copy_dir  /srv/shares           "$D/srv_shares"
    safe_copy_dir  /home/shares          "$D/home_shares"

    # Logs
    safe_copy_dir  /var/log/samba        "$D/log_samba"

    # Unit files (both Ubuntu and Rocky names) + drop-ins
    backup_unit    smbd.service          "$D/units"   # Ubuntu
    backup_unit    nmbd.service          "$D/units"   # Ubuntu
    backup_unit    smb.service           "$D/units"   # Rocky
    backup_unit    nmb.service           "$D/units"   # Rocky
    backup_unit    winbind.service       "$D/units"   # AD members
    backup_dropins "$D/dropins" smbd nmbd smb nmb winbind

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

    # --- Debian/Ubuntu layout ---
    safe_copy_dir  /etc/bind             "$D/etc_bind"
    safe_copy_dir  /var/lib/bind         "$D/var_lib_bind"
    safe_copy_dir  /var/cache/bind       "$D/var_cache_bind"
    safe_copy_file /etc/default/bind9    "$D/default_bind9"

    # --- RHEL/Rocky layout ---
    safe_copy_file /etc/named.conf               "$D/named.conf"
    safe_copy_file /etc/named.rfc1912.zones      "$D/named.rfc1912.zones"
    safe_copy_file /etc/named.root.key           "$D/named.root.key"
    safe_copy_file /etc/named.iscdlv.key         "$D/named.iscdlv.key"
    safe_copy_file /etc/rndc.key                 "$D/rndc.key"
    safe_copy_file /etc/rndc.conf                "$D/rndc.conf"
    safe_copy_dir  /etc/named                    "$D/etc_named"
    safe_copy_dir  /var/named                    "$D/var_named"
    safe_copy_file /etc/sysconfig/named          "$D/sysconfig_named"
    # If bind-chroot is installed, the real files live inside the chroot
    safe_copy_dir  /var/named/chroot             "$D/var_named_chroot"

    # Logs
    safe_copy_dir  /var/log/named        "$D/log_named"

    # Unit files + drop-ins
    backup_unit    bind9.service         "$D/units"   # Ubuntu
    backup_unit    named.service         "$D/units"   # Rocky
    backup_unit    named-chroot.service  "$D/units"   # Rocky w/ bind-chroot
    backup_dropins "$D/dropins" bind9 named named-chroot

    echo -e "${GREEN}[+] BIND DNS done${NC}\n"
    echo "dns: complete" >> "$MANIFEST"
}

# =============================================================================
# POSTGRESQL
#   Ubuntu: config in /etc/postgresql, data in /var/lib/postgresql
#   Rocky:  config + data both under /var/lib/pgsql/data, env in /etc/sysconfig/pgsql
# =============================================================================
backup_postgres() {
    echo -e "${YELLOW}[*] Backing up PostgreSQL...${NC}"
    local D="$BACKUP_DIR/postgres"
    mkdir -p "$D"

    # Config + data — Ubuntu layout
    safe_copy_dir  /etc/postgresql       "$D/etc_postgresql"
    safe_copy_dir  /var/lib/postgresql   "$D/var_lib_postgresql"
    safe_copy_dir  /var/log/postgresql   "$D/log_postgresql"

    # Config + data — Rocky layout
    safe_copy_dir  /var/lib/pgsql        "$D/var_lib_pgsql"
    safe_copy_dir  /etc/sysconfig/pgsql  "$D/sysconfig_pgsql"
    safe_copy_dir  /var/lib/pgsql/data/log "$D/log_pgsql_data"

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
            [[ -z "$DBNAME" ]] && continue
            sudo -u postgres pg_dump "$DBNAME" > "$DB_DIR/${DBNAME}_${TIMESTAMP}.sql" 2>/dev/null \
                && echo -e "  ${GREEN}[+] Dumped:${NC} $DBNAME" \
                || echo -e "  ${RED}[-] Failed:${NC} $DBNAME"
        done

        # Save roles separately (passwords, membership)
        sudo -u postgres pg_dumpall --roles-only > "$D/pg_roles_${TIMESTAMP}.sql" 2>/dev/null
    else
        echo -e "  ${YELLOW}[~] 'postgres' system user not found — skipping pg_dump${NC}"
    fi

    # Unit files + drop-ins
    backup_unit    postgresql.service    "$D/units"
    backup_dropins "$D/dropins" postgresql

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

{
    echo ""
    echo "Backup finished: $(date)"
} >> "$MANIFEST"
