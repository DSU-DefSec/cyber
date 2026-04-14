#!/bin/bash
# =============================================================================
# restore.sh — Companion restore script for backup.sh
# Usage:   sudo ./restore.sh <backup_dir> [service1 service2 ...] | all
# Example: sudo ./restore.sh /usb/backup_20260412_143021 apache2 ssh postgres
#
# Supported services:
#   apache2   (also: apache, httpd)
#   nginx
#   ssh       (also: openssh)
#   vsftpd    (also: ftp)
#   smb       (also: samba)
#   dns       (also: bind, named)
#   postgres  (also: postgresql, pg)
#   all       → restore every service found in the backup directory
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Pre-flight checks
# =============================================================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Must be run as root: sudo $0 ...${NC}"
    exit 1
fi

if [[ $# -lt 2 ]]; then
    echo -e "${YELLOW}Usage: $0 <backup_directory> [service1 service2 ...] | all${NC}"
    echo -e "  Services: apache2, nginx, ssh, vsftpd, smb, dns, postgres, all"
    exit 1
fi

BACKUP_DIR="$1"
shift  # remaining args are service names (or "all")

if [[ ! -d "$BACKUP_DIR" ]]; then
    echo -e "${RED}[!] Backup directory not found: $BACKUP_DIR${NC}"
    exit 1
fi

# Detect distro family — used to pick the right unit/path on each service
DISTRO_ID=""
DISTRO_LIKE=""
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"
    DISTRO_LIKE="${ID_LIKE:-}"
fi
case "${DISTRO_LIKE:-$DISTRO_ID}" in
    *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
    *rhel*|*fedora*|*centos*|rocky|almalinux) DISTRO_FAMILY="rhel" ;;
    *) DISTRO_FAMILY="unknown" ;;
esac

# If "all" passed, auto-detect services from backup subdirectory names
if [[ "$*" == "all" || "$*" == "ALL" ]]; then
    SERVICES=()
    [[ -d "$BACKUP_DIR/apache2" ]]  && SERVICES+=("apache2")
    [[ -d "$BACKUP_DIR/nginx" ]]    && SERVICES+=("nginx")
    [[ -d "$BACKUP_DIR/openssh" ]]  && SERVICES+=("ssh")
    [[ -d "$BACKUP_DIR/vsftpd" ]]   && SERVICES+=("vsftpd")
    [[ -d "$BACKUP_DIR/samba" ]]    && SERVICES+=("smb")
    [[ -d "$BACKUP_DIR/bind_dns" ]] && SERVICES+=("dns")
    [[ -d "$BACKUP_DIR/postgres" ]] && SERVICES+=("postgres")

    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        echo -e "${RED}[!] No recognizable service backups found in: $BACKUP_DIR${NC}"
        exit 1
    fi

    echo -e "${CYAN}[*] Auto-detected services to restore: ${SERVICES[*]}${NC}\n"
    set -- "${SERVICES[@]}"
fi

LOG="$BACKUP_DIR/RESTORE_LOG_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Restore started: $(date)"
    echo "Host: $(hostname)"
    echo "Distro: ${DISTRO_ID:-unknown} (family: $DISTRO_FAMILY)"
    echo "Backup dir: $BACKUP_DIR"
    echo "Services: $*"
    echo ""
} > "$LOG"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Restore started: $(date)${NC}"
echo -e "${CYAN} Source:  $BACKUP_DIR${NC}"
echo -e "${CYAN} Distro:  ${DISTRO_ID:-unknown} ($DISTRO_FAMILY)${NC}"
echo -e "${CYAN} Services: $*${NC}"
echo -e "${CYAN}============================================${NC}\n"

# =============================================================================
# Helpers
# =============================================================================

# CLEAN restore — removes destination first, then copies.
# Guarantees no attacker-modified files survive in config directories.
restore_dir_clean() {
    local src="$1"
    local dest="$2"
    local owner="${3:-}"

    if [[ ! -d "$src" ]]; then
        return 0
    fi

    echo -e "  ${GREEN}[+]${NC} $dest"
    rm -rf "$dest"
    mkdir -p "$(dirname "$dest")"
    if cp -rp "$src" "$dest"; then
        echo -e "     ${GREEN}✓ Restored${NC}"
    else
        echo -e "     ${RED}✗ Failed${NC}"
        return 1
    fi

    [[ -n "$owner" ]] && chown -R "$owner" "$dest" 2>/dev/null
    echo "  RESTORE DIR (clean): $src -> $dest" >> "$LOG"
}

# MERGE restore — copies into existing destination (safe for live data dirs).
restore_dir_merge() {
    local src="$1"
    local dest="$2"
    local owner="${3:-}"

    if [[ ! -d "$src" ]]; then
        return 0
    fi

    echo -e "  ${GREEN}[+]${NC} $dest (merge)"
    mkdir -p "$dest"
    if cp -rp "$src/." "$dest/"; then
        echo -e "     ${GREEN}✓ Restored${NC}"
    else
        echo -e "     ${RED}✗ Failed${NC}"
        return 1
    fi

    [[ -n "$owner" ]] && chown -R "$owner" "$dest" 2>/dev/null
    echo "  RESTORE DIR (merge): $src -> $dest" >> "$LOG"
}

# Restore a single file, overwriting destination.
restore_file() {
    local src="$1"
    local dest="$2"
    local owner="${3:-}"
    local mode="${4:-}"

    if [[ ! -f "$src" ]]; then
        return 0
    fi

    echo -e "  ${GREEN}[+]${NC} $dest"
    mkdir -p "$(dirname "$dest")"
    if cp -p "$src" "$dest"; then
        echo -e "     ${GREEN}✓ Restored${NC}"
    else
        echo -e "     ${RED}✗ Failed${NC}"
        return 1
    fi

    [[ -n "$owner" ]] && chown "$owner" "$dest" 2>/dev/null
    [[ -n "$mode" ]]  && chmod "$mode"  "$dest" 2>/dev/null
    echo "  RESTORE FILE: $src -> $dest" >> "$LOG"
}

# Restore systemd drop-in directories from backup's dropins/ subdir into
# /etc/systemd/system/. Triggers daemon-reload at the end if anything copied.
restore_dropins() {
    local dropdir="$1"
    [[ -d "$dropdir" ]] || return 0
    local copied=0
    for d in "$dropdir"/*.service.d; do
        [[ -d "$d" ]] || continue
        local name
        name=$(basename "$d")
        echo -e "  ${GREEN}[+]${NC} drop-in: /etc/systemd/system/$name"
        rm -rf "/etc/systemd/system/$name"
        cp -rp "$d" "/etc/systemd/system/$name" 2>/dev/null && copied=1
        echo "  RESTORE DROPIN: $d -> /etc/systemd/system/$name" >> "$LOG"
    done
    (( copied )) && systemctl daemon-reload 2>/dev/null
    return 0
}

# Restore vendor systemd unit files from backup's units/ subdir.
# Writes to /usr/lib/systemd/system (on Ubuntu /lib is a symlink to /usr/lib,
# so this works on both distros). Triggers daemon-reload if anything copied.
restore_units() {
    local unitsdir="$1"
    [[ -d "$unitsdir" ]] || return 0
    local target="/usr/lib/systemd/system"
    [[ -d "$target" ]] || target="/lib/systemd/system"
    [[ -d "$target" ]] || { mkdir -p "$target" 2>/dev/null || return 0; }
    local copied=0
    for unit_file in "$unitsdir"/*; do
        [[ -f "$unit_file" ]] || continue
        local name
        name=$(basename "$unit_file")
        echo -e "  ${GREEN}[+]${NC} unit: $target/$name"
        if cp -p "$unit_file" "$target/$name" 2>/dev/null; then
            chmod 644 "$target/$name" 2>/dev/null
            copied=1
        fi
        echo "  RESTORE UNIT: $unit_file -> $target/$name" >> "$LOG"
    done
    (( copied )) && systemctl daemon-reload 2>/dev/null
    return 0
}

# Restore SysV init scripts from backup's initd/ subdir into /etc/init.d/.
# Some Ubuntu services (ssh, apache2, samba) ship LSB wrappers there.
restore_initd() {
    local initdir="$1"
    [[ -d "$initdir" ]] || return 0
    mkdir -p /etc/init.d 2>/dev/null
    local copied=0
    for f in "$initdir"/*; do
        [[ -f "$f" ]] || continue
        local name
        name=$(basename "$f")
        echo -e "  ${GREEN}[+]${NC} init.d: /etc/init.d/$name"
        cp -p "$f" "/etc/init.d/$name" 2>/dev/null && copied=1
        chmod 755 "/etc/init.d/$name" 2>/dev/null
        echo "  RESTORE INITD: $f -> /etc/init.d/$name" >> "$LOG"
    done
    # systemd-sysv-generator only synthesizes wrappers at daemon-reload time
    (( copied )) && systemctl daemon-reload 2>/dev/null
    return 0
}

# Detect the active systemd unit name for a service (handles distro naming differences).
detect_unit() {
    for name in "$@"; do
        if systemctl list-unit-files --type=service 2>/dev/null | grep -q "^${name}\.service"; then
            echo "$name"
            return 0
        fi
    done
}

svc_stop() {
    local unit="$1"
    [[ -z "$unit" ]] && return
    echo -e "  ${YELLOW}[*] Stopping $unit...${NC}"
    systemctl stop "$unit" 2>/dev/null || true
}

# Unmask before starting — tables.sh (or any prior hardening) may have masked
# the unit by creating /etc/systemd/system/<unit> -> /dev/null, which silently
# overrides the vendor unit we just restored. unmask removes that symlink.
svc_start() {
    local unit="$1"
    [[ -z "$unit" ]] && return
    systemctl unmask "$unit" 2>/dev/null
    echo -e "  ${YELLOW}[*] Starting $unit...${NC}"
    if systemctl start "$unit" 2>/dev/null; then
        echo -e "  ${GREEN}[+] $unit started${NC}"
    else
        echo -e "  ${RED}[-] Failed to start $unit — check: systemctl status $unit${NC}"
    fi
}

# Reload preferred over restart — avoids dropping active connections (critical for SSH).
svc_reload() {
    local unit="$1"
    [[ -z "$unit" ]] && return
    systemctl unmask "$unit" 2>/dev/null
    echo -e "  ${YELLOW}[*] Reloading $unit config...${NC}"
    if systemctl reload "$unit" 2>/dev/null; then
        echo -e "  ${GREEN}[+] $unit reloaded${NC}"
    else
        echo -e "  ${YELLOW}[~] Reload unsupported, falling back to restart...${NC}"
        if systemctl restart "$unit" 2>/dev/null; then
            echo -e "  ${GREEN}[+] $unit restarted${NC}"
        else
            echo -e "  ${RED}[-] Failed — check: systemctl status $unit${NC}"
        fi
    fi
}

# =============================================================================
# APACHE2 / HTTPD
# =============================================================================
restore_apache2() {
    echo -e "${YELLOW}[*] Restoring Apache2...${NC}"
    local B="$BACKUP_DIR/apache2"
    local UNIT
    UNIT=$(detect_unit apache2 httpd)

    svc_stop "$UNIT"

    # Configs — CLEAN (wipes any attacker-modified configs)
    restore_dir_clean "$B/etc_apache2" /etc/apache2 "root:root"
    restore_dir_clean "$B/etc_httpd"   /etc/httpd   "root:root"

    # Env / defaults
    restore_file "$B/default_apache2" /etc/default/apache2 "root:root" "644"
    restore_file "$B/sysconfig_httpd" /etc/sysconfig/httpd "root:root" "644"

    # Web root — MERGE (preserves any files not captured in backup)
    restore_dir_merge "$B/var_www" /var/www

    # TLS material
    restore_dir_clean "$B/letsencrypt"     /etc/letsencrypt
    restore_dir_clean "$B/ssl_private"     /etc/ssl/private     "root:root"
    restore_dir_clean "$B/pki_tls_private" /etc/pki/tls/private "root:root"
    chmod 700 /etc/ssl/private     2>/dev/null
    chmod 700 /etc/pki/tls/private 2>/dev/null

    # Unit files + drop-ins + init.d (BEFORE svc_start)
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    # If we just restored the unit, detect_unit may now succeed where it didn't
    [[ -z "$UNIT" ]] && UNIT=$(detect_unit apache2 httpd)

    # Fix web root ownership (www-data on Debian, apache on RHEL)
    if getent group www-data &>/dev/null; then
        chown -R www-data:www-data /var/www 2>/dev/null
    elif getent group apache &>/dev/null; then
        chown -R apache:apache /var/www 2>/dev/null
    fi

    svc_start "$UNIT"
    echo -e "${GREEN}[+] Apache2 restore complete${NC}\n"
    echo "apache2: restored" >> "$LOG"
}

# =============================================================================
# NGINX
# =============================================================================
restore_nginx() {
    echo -e "${YELLOW}[*] Restoring Nginx...${NC}"
    local B="$BACKUP_DIR/nginx"
    local UNIT
    UNIT=$(detect_unit nginx)

    svc_stop "$UNIT"

    # Config — CLEAN
    restore_dir_clean "$B/etc_nginx" /etc/nginx "root:root"

    # Env / defaults
    restore_file "$B/default_nginx"   /etc/default/nginx   "root:root" "644"
    restore_file "$B/sysconfig_nginx" /etc/sysconfig/nginx "root:root" "644"

    # Web roots — MERGE
    restore_dir_merge "$B/var_www" /var/www
    restore_dir_merge "$B/html"    /usr/share/nginx/html

    # TLS material
    restore_dir_clean "$B/letsencrypt"     /etc/letsencrypt
    restore_dir_clean "$B/ssl_private"     /etc/ssl/private     "root:root"
    restore_dir_clean "$B/pki_tls_private" /etc/pki/tls/private "root:root"
    chmod 700 /etc/ssl/private     2>/dev/null
    chmod 700 /etc/pki/tls/private 2>/dev/null

    # Unit files + drop-ins + init.d (BEFORE svc_start)
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    [[ -z "$UNIT" ]] && UNIT=$(detect_unit nginx)

    # Fix ownership
    if getent group www-data &>/dev/null; then
        chown -R www-data:www-data /var/www 2>/dev/null
    elif getent group nginx &>/dev/null; then
        chown -R nginx:nginx /var/www 2>/dev/null
    fi

    svc_start "$UNIT"
    echo -e "${GREEN}[+] Nginx restore complete${NC}\n"
    echo "nginx: restored" >> "$LOG"
}

# =============================================================================
# OPENSSH
# IMPORTANT: Uses reload instead of restart to avoid dropping your SSH session.
# =============================================================================
restore_ssh() {
    echo -e "${YELLOW}[*] Restoring OpenSSH...${NC}"
    local B="$BACKUP_DIR/openssh"
    local UNIT
    UNIT=$(detect_unit ssh sshd)

    echo -e "  ${CYAN}[!] SSH config will be reloaded (not restarted) — active sessions stay alive${NC}"

    # /etc/ssh — CLEAN replace (host keys live here; attacker may have swapped them)
    restore_dir_clean "$B/etc_ssh" /etc/ssh "root:root"

    # Lock down host key permissions (SSH refuses to start if these are too open)
    if [[ -d /etc/ssh ]]; then
        chmod 600 /etc/ssh/*_key       2>/dev/null
        chmod 644 /etc/ssh/*_key.pub   2>/dev/null
        chmod 644 /etc/ssh/sshd_config 2>/dev/null
    fi

    # PAM config
    restore_file "$B/pam_sshd" /etc/pam.d/sshd "root:root" "644"

    # Env / defaults
    restore_file "$B/default_ssh"    /etc/default/ssh    "root:root" "644"
    restore_file "$B/sysconfig_sshd" /etc/sysconfig/sshd "root:root" "644"

    # Unit files + drop-ins + init.d (BEFORE svc_reload)
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    [[ -z "$UNIT" ]] && UNIT=$(detect_unit ssh sshd)

    # Per-user .ssh directories (authorized_keys, known_hosts, etc.)
    if [[ -d "$B/user_ssh_dirs" ]]; then
        echo -e "  ${YELLOW}[*] Restoring user .ssh directories...${NC}"
        for USER_SSH_BACKUP in "$B/user_ssh_dirs"/*; do
            [[ ! -d "$USER_SSH_BACKUP" ]] && continue

            FOLDER_NAME=$(basename "$USER_SSH_BACKUP")
            USERNAME="${FOLDER_NAME%_ssh}"

            HOME_DIR=$(getent passwd "$USERNAME" | cut -d: -f6)
            if [[ -z "$HOME_DIR" ]]; then
                echo -e "  ${YELLOW}[~] User '$USERNAME' not on this system — skipping${NC}"
                continue
            fi

            echo -e "  ${GREEN}[+]${NC} $HOME_DIR/.ssh ($USERNAME)"
            restore_dir_clean "$USER_SSH_BACKUP" "$HOME_DIR/.ssh"

            # SSH is strict about permissions — enforce them
            chown -R "${USERNAME}:${USERNAME}" "$HOME_DIR/.ssh" 2>/dev/null
            chmod 700 "$HOME_DIR/.ssh"                          2>/dev/null
            chmod 600 "$HOME_DIR/.ssh/"*                        2>/dev/null
            chmod 644 "$HOME_DIR/.ssh/"*.pub                    2>/dev/null
            chmod 644 "$HOME_DIR/.ssh/known_hosts"              2>/dev/null
            chmod 600 "$HOME_DIR/.ssh/authorized_keys"          2>/dev/null
        done
    fi

    # Unmask socket units too — tables.sh masks both the service AND the socket.
    # svc_reload only handles the .service unit, so sockets need explicit unmask.
    systemctl unmask ssh.socket sshd.socket 2>/dev/null

    # Reload (not restart) so your session stays alive
    svc_reload "$UNIT"
    echo -e "${GREEN}[+] OpenSSH restore complete${NC}\n"
    echo "ssh: restored" >> "$LOG"
}

# =============================================================================
# VSFTPD
# =============================================================================
restore_vsftpd() {
    echo -e "${YELLOW}[*] Restoring vsftpd...${NC}"
    local B="$BACKUP_DIR/vsftpd"
    local UNIT
    UNIT=$(detect_unit vsftpd)

    svc_stop "$UNIT"

    # Configs
    restore_file      "$B/vsftpd.conf"         /etc/vsftpd.conf        "root:root" "600"
    restore_dir_clean "$B/etc_vsftpd"          /etc/vsftpd             "root:root"
    restore_file      "$B/vsftpd.userlist"     /etc/vsftpd.userlist    "root:root" "644"
    restore_file      "$B/ftpusers"            /etc/ftpusers           "root:root" "644"
    restore_file      "$B/vsftpd.chroot_list"  /etc/vsftpd.chroot_list "root:root" "644"
    restore_file      "$B/pam_vsftpd"          /etc/pam.d/vsftpd       "root:root" "644"

    # Env / defaults
    restore_file      "$B/sysconfig_vsftpd"    /etc/sysconfig/vsftpd   "root:root" "644"
    restore_file      "$B/default_vsftpd"      /etc/default/vsftpd     "root:root" "644"

    # Unit files + drop-ins + init.d (BEFORE svc_start)
    restore_units     "$B/units"
    restore_dropins   "$B/dropins"
    restore_initd     "$B/initd"

    [[ -z "$UNIT" ]] && UNIT=$(detect_unit vsftpd)

    # FTP data — MERGE
    restore_dir_merge "$B/srv_ftp"  /srv/ftp  "ftp:ftp"
    restore_dir_merge "$B/var_ftp"  /var/ftp  "ftp:ftp"
    restore_dir_merge "$B/home_ftp" /home/ftp "ftp:ftp"

    svc_start "$UNIT"
    echo -e "${GREEN}[+] vsftpd restore complete${NC}\n"
    echo "vsftpd: restored" >> "$LOG"
}

# =============================================================================
# SAMBA / SMB
#   Unit names: smbd/nmbd on Debian/Ubuntu, smb/nmb on RHEL/Rocky.
# =============================================================================
restore_smb() {
    echo -e "${YELLOW}[*] Restoring Samba (SMB)...${NC}"
    local B="$BACKUP_DIR/samba"
    local MAIN NETBIOS WINBIND
    MAIN=$(detect_unit smbd smb)
    NETBIOS=$(detect_unit nmbd nmb)
    WINBIND=$(detect_unit winbind)

    svc_stop "$WINBIND"
    svc_stop "$NETBIOS"
    svc_stop "$MAIN"

    # Config — CLEAN
    restore_dir_clean "$B/etc_samba" /etc/samba "root:root"

    # Env / defaults
    restore_file "$B/default_samba"   /etc/default/samba   "root:root" "644"
    restore_file "$B/sysconfig_samba" /etc/sysconfig/samba "root:root" "644"

    # Samba TDB databases (user accounts + secrets) — CLEAN
    restore_dir_clean "$B/var_lib_samba" /var/lib/samba
    chown -R root:root /var/lib/samba 2>/dev/null

    # Shared data directories — MERGE
    restore_dir_merge "$B/srv_samba"   /srv/samba
    restore_dir_merge "$B/srv_shares"  /srv/shares
    restore_dir_merge "$B/home_shares" /home/shares

    # Unit files + drop-ins + init.d (BEFORE svc_start)
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    [[ -z "$MAIN" ]]    && MAIN=$(detect_unit smbd smb)
    [[ -z "$NETBIOS" ]] && NETBIOS=$(detect_unit nmbd nmb)
    [[ -z "$WINBIND" ]] && WINBIND=$(detect_unit winbind)

    svc_start "$MAIN"
    svc_start "$NETBIOS"
    svc_start "$WINBIND"
    echo -e "${GREEN}[+] Samba restore complete${NC}\n"
    echo "samba: restored" >> "$LOG"
}

# =============================================================================
# BIND DNS
# =============================================================================
restore_dns() {
    echo -e "${YELLOW}[*] Restoring BIND DNS...${NC}"
    local B="$BACKUP_DIR/bind_dns"
    local UNIT
    UNIT=$(detect_unit bind9 named-chroot named)

    svc_stop "$UNIT"

    # --- Debian/Ubuntu layout ---
    restore_dir_clean "$B/etc_bind"       /etc/bind       "bind:bind"
    restore_dir_clean "$B/var_lib_bind"   /var/lib/bind   "bind:bind"
    restore_dir_clean "$B/var_cache_bind" /var/cache/bind "bind:bind"
    restore_file      "$B/default_bind9"  /etc/default/bind9 "root:root" "644"

    # --- RHEL/Rocky layout ---
    restore_file      "$B/named.conf"            /etc/named.conf            "root:named" "640"
    restore_file      "$B/named.rfc1912.zones"   /etc/named.rfc1912.zones   "root:named" "640"
    restore_file      "$B/named.root.key"        /etc/named.root.key        "root:named" "640"
    restore_file      "$B/named.iscdlv.key"      /etc/named.iscdlv.key      "root:named" "640"
    restore_file      "$B/rndc.key"              /etc/rndc.key              "root:named" "640"
    restore_file      "$B/rndc.conf"             /etc/rndc.conf             "root:named" "640"
    restore_dir_clean "$B/etc_named"             /etc/named                 "root:named"
    restore_dir_clean "$B/var_named"             /var/named
    chown -R named:named /var/named 2>/dev/null

    # bind-chroot (Rocky optional)
    restore_dir_clean "$B/var_named_chroot"      /var/named/chroot
    [[ -d /var/named/chroot ]] && chown -R named:named /var/named/chroot 2>/dev/null

    # Env / defaults
    restore_file "$B/sysconfig_named" /etc/sysconfig/named "root:root" "644"

    # Unit files + drop-ins + init.d (BEFORE svc_start)
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    [[ -z "$UNIT" ]] && UNIT=$(detect_unit bind9 named-chroot named)

    # BIND is fussy about directory permissions
    chmod 755 /etc/bind     2>/dev/null
    chmod 755 /var/lib/bind 2>/dev/null

    svc_start "$UNIT"
    echo -e "${GREEN}[+] BIND DNS restore complete${NC}\n"
    echo "dns: restored" >> "$LOG"
}

# =============================================================================
# POSTGRESQL
# Restore strategy (in order of preference):
#   1. Individual per-database SQL dumps  (most reliable, distro-agnostic)
#   2. pg_dumpall SQL dump                (fallback)
#   3. Raw data directory copy            (last resort if no SQL available)
#
# Path layout differs by distro:
#   Ubuntu: config in /etc/postgresql, data in /var/lib/postgresql
#   Rocky:  config + data both under /var/lib/pgsql/data
# =============================================================================
restore_postgres() {
    echo -e "${YELLOW}[*] Restoring PostgreSQL...${NC}"
    local B="$BACKUP_DIR/postgres"
    local UNIT
    UNIT=$(detect_unit postgresql postgresql@14-main postgresql@15-main postgresql@16-main)
    [[ -z "$UNIT" ]] && UNIT="postgresql"

    # Restore config files first (whichever distro this is)
    restore_dir_clean "$B/etc_postgresql"     /etc/postgresql     "postgres:postgres"
    restore_dir_clean "$B/sysconfig_pgsql"    /etc/sysconfig/pgsql "root:root"

    # Unit files + drop-ins + init.d
    restore_units   "$B/units"
    restore_dropins "$B/dropins"
    restore_initd   "$B/initd"

    [[ -z "$UNIT" ]] && UNIT=$(detect_unit postgresql postgresql@14-main postgresql@15-main postgresql@16-main)
    [[ -z "$UNIT" ]] && UNIT="postgresql"

    # Ensure PostgreSQL is running so we can run SQL commands
    echo -e "  ${YELLOW}[*] Ensuring PostgreSQL is running...${NC}"
    systemctl unmask "$UNIT" 2>/dev/null
    systemctl start  "$UNIT" 2>/dev/null
    sleep 2

    # Check if we can connect
    if ! sudo -u postgres psql -c "SELECT 1;" &>/dev/null; then
        echo -e "  ${RED}[!] Cannot connect to PostgreSQL — falling back to raw data directory restore${NC}"
        svc_stop "$UNIT"

        # Try whichever data dir is in the backup
        if [[ -d "$B/var_lib_postgresql" ]]; then
            restore_dir_clean "$B/var_lib_postgresql" /var/lib/postgresql
            chown -R postgres:postgres /var/lib/postgresql 2>/dev/null
        fi
        if [[ -d "$B/var_lib_pgsql" ]]; then
            restore_dir_clean "$B/var_lib_pgsql" /var/lib/pgsql
            chown -R postgres:postgres /var/lib/pgsql 2>/dev/null
        fi

        svc_start "$UNIT"
        echo -e "${GREEN}[+] PostgreSQL restore complete (data dir fallback)${NC}\n"
        echo "postgres: restored (data dir fallback)" >> "$LOG"
        return
    fi

    # Restore roles first (passwords, memberships) so per-DB owners exist
    if compgen -G "$B/pg_roles_*.sql" > /dev/null; then
        local ROLES_FILE
        ROLES_FILE=$(ls "$B"/pg_roles_*.sql | head -1)
        echo -e "  ${YELLOW}[*] Restoring roles from $(basename "$ROLES_FILE")${NC}"
        sudo -u postgres psql -f "$ROLES_FILE" postgres &>/dev/null \
            && echo -e "  ${GREEN}[+] Roles restored${NC}" \
            || echo -e "  ${YELLOW}[~] Some role statements failed (often: role already exists)${NC}"
        echo "  PG: roles restored from $ROLES_FILE" >> "$LOG"
    fi

    # --- Restore from individual database SQL dumps (preferred) ---
    local DB_DIR="$B/individual_dbs"

    if [[ -d "$DB_DIR" ]] && compgen -G "$DB_DIR/*.sql" > /dev/null; then
        echo -e "  ${YELLOW}[*] Restoring from individual database dumps...${NC}"

        for SQL_FILE in "$DB_DIR"/*.sql; do
            [[ ! -f "$SQL_FILE" ]] && continue

            FILENAME=$(basename "$SQL_FILE")
            DBNAME=$(echo "$FILENAME" | sed 's/_[0-9]\{8\}_[0-9]\{6\}\.sql$//')

            echo -e "  ${YELLOW}[*] Restoring database: $DBNAME${NC}"

            # Kick out any existing connections to this DB
            sudo -u postgres psql -c \
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                 WHERE datname = '$DBNAME' AND pid <> pg_backend_pid();" &>/dev/null

            # Drop and recreate clean
            sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$DBNAME\";" &>/dev/null
            if ! sudo -u postgres psql -c "CREATE DATABASE \"$DBNAME\";" 2>/dev/null; then
                echo -e "     ${RED}✗ Could not create database $DBNAME${NC}"
                continue
            fi

            # Restore data
            if sudo -u postgres psql -d "$DBNAME" -f "$SQL_FILE" &>/dev/null; then
                echo -e "     ${GREEN}✓ $DBNAME restored${NC}"
            else
                echo -e "     ${RED}✗ $DBNAME restore had errors — verify manually${NC}"
            fi

            echo "  PG DB: $DBNAME restored from $SQL_FILE" >> "$LOG"
        done

    # --- Fallback: pg_dumpall SQL file ---
    elif compgen -G "$B/pg_dumpall_*.sql" > /dev/null; then
        local DUMPFILE
        DUMPFILE=$(ls "$B"/pg_dumpall_*.sql | head -1)
        echo -e "  ${YELLOW}[*] Restoring from pg_dumpall: $(basename "$DUMPFILE")${NC}"
        echo -e "  ${CYAN}[!] Note: 'already exists' errors are normal if databases weren't dropped first${NC}"

        sudo -u postgres psql -f "$DUMPFILE" postgres &>/dev/null || true
        echo -e "  ${GREEN}[+] pg_dumpall restore complete${NC}"
        echo "  PG: pg_dumpall restore from $DUMPFILE" >> "$LOG"

    else
        echo -e "  ${RED}[!] No SQL dumps found — attempting raw data directory restore${NC}"
        svc_stop "$UNIT"

        if [[ -d "$B/var_lib_postgresql" ]]; then
            restore_dir_clean "$B/var_lib_postgresql" /var/lib/postgresql
            chown -R postgres:postgres /var/lib/postgresql 2>/dev/null
        fi
        if [[ -d "$B/var_lib_pgsql" ]]; then
            restore_dir_clean "$B/var_lib_pgsql" /var/lib/pgsql
            chown -R postgres:postgres /var/lib/pgsql 2>/dev/null
        fi

        svc_start "$UNIT"
        echo "postgres: restored (data dir, no SQL found)" >> "$LOG"
    fi

    echo -e "${GREEN}[+] PostgreSQL restore complete${NC}\n"
    echo "postgres: restored" >> "$LOG"
}

# =============================================================================
# MAIN — iterate requested services
# =============================================================================
for SVC in "$@"; do
    case "$SVC" in
        apache2|apache|httpd)   restore_apache2  ;;
        nginx)                  restore_nginx    ;;
        ssh|openssh)            restore_ssh      ;;
        vsftpd|ftp)             restore_vsftpd   ;;
        smb|samba)              restore_smb      ;;
        dns|bind|named)         restore_dns      ;;
        postgres|postgresql|pg) restore_postgres ;;
        *)
            echo -e "${RED}[!] Unknown service: '$SVC' — skipping${NC}"
            echo -e "    Available: apache2, nginx, ssh, vsftpd, smb, dns, postgres, all"
            ;;
    esac
done

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Restore complete: $(date)${NC}"
echo -e "${CYAN} Log written to: $LOG${NC}"
echo -e "${CYAN}============================================${NC}\n"
echo -e "${YELLOW}Tip: check service health with:${NC}"
echo -e "  systemctl status apache2 nginx ssh vsftpd smbd bind9 postgresql"
echo ""

{
    echo ""
    echo "Restore finished: $(date)"
} >> "$LOG"
