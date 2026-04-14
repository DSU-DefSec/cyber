#!/usr/bin/env bash
# =============================================================================
# config_scanner.sh — Security Configuration Scanner
# Audits service configuration files for common insecure settings.
#
# Supported services:
#   apache2 (apache, httpd)   nginx    openssh (ssh, sshd)
#   vsftpd  (ftp)             samba    (smb)   bind (dns, named)
#   postgres (postgresql, pgsql)
#
# Compatible with : Ubuntu 24 LTS · Rocky Linux 8 / 9
# Requires        : bash 4+, grep, sed, awk  (all pre-installed on both)
# Recommended     : Run as root so all config files are readable
#
# Usage:
#   ./config_scanner.sh -s openssh nginx postgres
#   ./config_scanner.sh -s all
#   ./config_scanner.sh -s all -o report.txt
#   ./config_scanner.sh -s all --severity HIGH
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# Severity
# ─────────────────────────────────────────────────────────────────────────────

sev_num() {   # lower number = higher severity
    case "${1^^}" in
        CRITICAL) echo 0 ;; HIGH) echo 1 ;; MEDIUM) echo 2 ;; LOW) echo 3 ;;
        INFO)     echo 4 ;; *)    echo 99 ;;
    esac
}

SEVERITY_FILTER=""   # empty means show everything

passes_filter() {
    [[ -z "$SEVERITY_FILTER" ]] && return 0
    local n f
    n=$(sev_num "$1"); f=$(sev_num "$SEVERITY_FILTER")
    (( n <= f ))
}

# ─────────────────────────────────────────────────────────────────────────────
# Finding storage  (parallel arrays, one entry per finding)
# ─────────────────────────────────────────────────────────────────────────────

declare -a F_SVC=() F_SEV=() F_TITLE=() F_DESC=() F_FIX=() F_PATH=()
F_N=0

# add <service> <severity> <title> <description> <fix> [path]
add() {
    F_SVC[$F_N]="$1";  F_SEV[$F_N]="$2";   F_TITLE[$F_N]="$3"
    F_DESC[$F_N]="$4"; F_FIX[$F_N]="$5";   F_PATH[$F_N]="${6:-}"
    (( F_N++ )) || true
}

# ─────────────────────────────────────────────────────────────────────────────
# Config file helpers
# ─────────────────────────────────────────────────────────────────────────────

BODY=""        # content of all config files for the current service (concatenated)
FIRST_PATH=""  # first config file path found

# Load one or more glob patterns into BODY / FIRST_PATH.
# Returns 1 if nothing was found.
load_configs() {
    BODY=""; FIRST_PATH=""
    local found=0 f txt old_nullglob
    old_nullglob=$(shopt -p nullglob)
    shopt -s nullglob
    for pattern in "$@"; do
        for f in $pattern; do
            [[ -f "$f" ]] || continue
            txt=$(cat "$f" 2>/dev/null) || continue
            BODY+=$'\n'"$txt"
            [[ -z "$FIRST_PATH" ]] && FIRST_PATH="$f"
            found=1
        done
    done
    eval "$old_nullglob"
    return $(( 1 - found ))
}

_VAL=""   # return slot for get_dir / get_eq

# Extract value from "key value" directives (space-separated), e.g. sshd_config
get_dir() {
    _VAL=""
    local key="$1"
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*${key}[[:space:]]+" \
        | grep -v '^[[:space:]]*#' \
        | head -1 \
        | sed -E "s/^[[:space:]]*${key}[[:space:]]+//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

# Extract value from "key = value" directives (equals-separated), e.g. vsftpd / postgresql.conf
get_eq() {
    _VAL=""
    local key="$1"
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*${key}[[:space:]]*=" \
        | grep -v '^[[:space:]]*#' \
        | head -1 \
        | sed -E "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

# Returns 0 (true) if BODY matches an extended regex (case-insensitive)
body_has() {
    printf '%s\n' "$BODY" | grep -qiE "$1"
}

# ─────────────────────────────────────────────────────────────────────────────
# Apache2
# ─────────────────────────────────────────────────────────────────────────────

check_apache2() {
    load_configs \
        '/etc/apache2/apache2.conf' \
        '/etc/apache2/conf-enabled/*.conf' \
        '/etc/apache2/sites-enabled/*.conf' \
        '/etc/httpd/conf/httpd.conf' \
        '/etc/httpd/conf.d/*.conf' || {
        add apache2 INFO 'Config not found' \
            'No Apache2/httpd config files found at standard paths.' \
            'Ensure Apache2 is installed (apt/dnf install apache2/httpd).' ''
        return
    }

    local v

    # ServerTokens
    get_dir 'ServerTokens'; v="${_VAL,,}"
    if [[ -z "$v" || ( "$v" != 'prod' && "$v" != 'productonly' ) ]]; then
        add apache2 MEDIUM 'ServerTokens exposes version info' \
            "ServerTokens = \"${_VAL:-Full (default)}\" — Apache version and OS details leak into every HTTP response header." \
            'Set:  ServerTokens Prod' "$FIRST_PATH"
    fi

    # ServerSignature
    get_dir 'ServerSignature'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" != 'off' ]]; then
        add apache2 LOW 'ServerSignature appends server info to error pages' \
            "ServerSignature = \"${_VAL:-On (default)}\" — version details are embedded in 4xx/5xx error responses." \
            'Set:  ServerSignature Off' "$FIRST_PATH"
    fi

    # TraceEnable
    get_dir 'TraceEnable'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" != 'off' ]]; then
        add apache2 MEDIUM 'HTTP TRACE method enabled' \
            'TraceEnable is not Off — TRACE can be abused in cross-site tracing (XST) attacks to steal cookies.' \
            'Set:  TraceEnable Off' "$FIRST_PATH"
    fi

    # Directory listing
    if body_has 'Options[[:space:]][^#]*\bIndexes\b'; then
        add apache2 HIGH 'Directory listing enabled (Options Indexes)' \
            'One or more Directory blocks include "Indexes" — directory contents are exposed to any browser.' \
            'Remove "Indexes" from all Options directives.' "$FIRST_PATH"
    fi

    # FollowSymLinks without SymLinksIfOwnerMatch
    if body_has 'Options[[:space:]][^#]*\bFollowSymLinks\b' && \
       ! body_has 'Options[[:space:]][^#]*\bSymLinksIfOwnerMatch\b'; then
        add apache2 MEDIUM 'FollowSymLinks without SymLinksIfOwnerMatch' \
            'Unrestricted symlink following can allow attackers to escape the document root.' \
            'Replace "FollowSymLinks" with "SymLinksIfOwnerMatch" wherever possible.' "$FIRST_PATH"
    fi

    # AllowOverride All
    if body_has '^[[:space:]]*AllowOverride[[:space:]]+All\b'; then
        add apache2 MEDIUM 'AllowOverride All in use' \
            '"AllowOverride All" lets .htaccess files override any server security directive.' \
            'Restrict AllowOverride to only the specific directives your application requires.' "$FIRST_PATH"
    fi

    # Weak TLS protocols
    local proto
    for proto in 'SSLv2' 'SSLv3' 'TLSv1 ' 'TLSv1\.1'; do
        if body_has "SSLProtocol[[:space:]][^#]*${proto}"; then
            local clean="${proto// /}"
            add apache2 HIGH "Deprecated TLS protocol enabled: ${clean}" \
                "\"${clean}\" is explicitly permitted in SSLProtocol — it has known cryptographic vulnerabilities." \
                'Set:  SSLProtocol TLSv1.2 TLSv1.3' "$FIRST_PATH"
        fi
    done

    # Missing security response headers
    local hdr; declare -A _H=(
        ['X-Frame-Options']='MEDIUM:Header always set X-Frame-Options "SAMEORIGIN"'
        ['X-Content-Type-Options']='LOW:Header always set X-Content-Type-Options "nosniff"'
        ['Strict-Transport-Security']='MEDIUM:Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
        ['X-XSS-Protection']='LOW:Header always set X-XSS-Protection "1; mode=block"'
    )
    for hdr in "${!_H[@]}"; do
        if ! body_has "Header[[:space:]][^#]*${hdr}"; then
            local sev rec
            IFS=':' read -r sev rec <<< "${_H[$hdr]}"
            add apache2 "$sev" "Missing security header: ${hdr}" \
                "\"${hdr}\" is not configured in any Apache config file." \
                "Add:  ${rec}"
        fi
    done
    unset _H

    # /server-status without IP restriction
    if body_has '<Location[[:space:]][^>]*/server-status'; then
        if ! body_has 'Require[[:space:]]+(ip|local|host)'; then
            add apache2 HIGH '/server-status exposed without IP restriction' \
                'mod_status is enabled but has no "Require ip" guard — server internals are publicly accessible.' \
                'Add "Require ip 127.0.0.1" inside the /server-status Location block.' "$FIRST_PATH"
        fi
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Nginx
# ─────────────────────────────────────────────────────────────────────────────

check_nginx() {
    load_configs \
        '/etc/nginx/nginx.conf' \
        '/etc/nginx/conf.d/*.conf' \
        '/etc/nginx/sites-enabled/*.conf' || {
        add nginx INFO 'Config not found' \
            'No Nginx config files found at standard paths.' \
            'Ensure Nginx is installed (apt/dnf install nginx).' ''
        return
    }

    local v

    # server_tokens
    if ! body_has '^[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;'; then
        add nginx MEDIUM 'server_tokens not disabled' \
            'Nginx version is advertised in HTTP response headers and default error pages.' \
            'Add inside the http { } block:  server_tokens off;'
    fi

    # autoindex
    if body_has '^[[:space:]]*autoindex[[:space:]]+on[[:space:]]*;'; then
        add nginx HIGH 'Directory listing enabled (autoindex on)' \
            '"autoindex on" exposes directory contents — attackers can enumerate all served files.' \
            'Set:  autoindex off;  (or remove — default is off)' "$FIRST_PATH"
    fi

    # ssl_protocols
    local proto_line
    proto_line=$(printf '%s\n' "$BODY" | grep -iE 'ssl_protocols[[:space:]]+' | head -1)
    if [[ -n "$proto_line" ]]; then
        local proto
        for proto in 'SSLv2' 'SSLv3' 'TLSv1 ' 'TLSv1\.1'; do
            if printf '%s\n' "$proto_line" | grep -qiE "$proto"; then
                local clean="${proto// /}"
                add nginx HIGH "Weak TLS protocol in ssl_protocols: ${clean}" \
                    "\"${clean}\" is a deprecated protocol with known cryptographic weaknesses." \
                    'Set:  ssl_protocols TLSv1.2 TLSv1.3;' "$FIRST_PATH"
            fi
        done
    else
        add nginx MEDIUM 'ssl_protocols not explicitly configured' \
            'Without ssl_protocols, the default may include weak protocols depending on the Nginx/OpenSSL version.' \
            'Explicitly set:  ssl_protocols TLSv1.2 TLSv1.3;' "$FIRST_PATH"
    fi

    # ssl_prefer_server_ciphers
    if ! body_has '^[[:space:]]*ssl_prefer_server_ciphers[[:space:]]+on[[:space:]]*;'; then
        add nginx LOW 'ssl_prefer_server_ciphers not enforced' \
            'Clients may negotiate weaker ciphers when server cipher preference is not set.' \
            'Add:  ssl_prefer_server_ciphers on;' "$FIRST_PATH"
    fi

    # Missing security response headers
    local hdr; declare -A _H=(
        ['X-Frame-Options']='MEDIUM:add_header X-Frame-Options "SAMEORIGIN" always;'
        ['X-Content-Type-Options']='LOW:add_header X-Content-Type-Options "nosniff" always;'
        ['Strict-Transport-Security']='MEDIUM:add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
        ['Content-Security-Policy']='LOW:add_header Content-Security-Policy "default-src '"'"'self'"'"';" always;'
    )
    for hdr in "${!_H[@]}"; do
        if ! body_has "add_header[[:space:]][^#]*${hdr}"; then
            local sev rec
            IFS=':' read -r sev rec <<< "${_H[$hdr]}"
            add nginx "$sev" "Missing security header: ${hdr}" \
                "\"${hdr}\" is not configured in any Nginx config file." \
                "Add:  ${rec}"
        fi
    done
    unset _H

    # client_max_body_size
    if ! body_has 'client_max_body_size'; then
        add nginx LOW 'client_max_body_size not configured' \
            'Default 1 MB upload cap may be too permissive for some apps and too strict for others.' \
            'Explicitly set:  client_max_body_size <value>;  in the http { } block.' "$FIRST_PATH"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# OpenSSH
# ─────────────────────────────────────────────────────────────────────────────

check_openssh() {
    load_configs '/etc/ssh/sshd_config' '/etc/sshd_config' || {
        add openssh INFO 'Config not found' \
            'sshd_config not found. Ensure OpenSSH server is installed.' \
            'Ubuntu: apt install openssh-server  |  Rocky: dnf install openssh-server' ''
        return
    }

    local v

    # PermitRootLogin
    get_dir 'PermitRootLogin'; v="${_VAL,,}"
    if [[ -z "$v" || ( "$v" != 'no' && "$v" != 'prohibit-password' && "$v" != 'forced-commands-only' ) ]]; then
        add openssh CRITICAL 'Root login permitted' \
            "PermitRootLogin = \"${_VAL:-yes (default)}\" — direct root SSH access bypasses user accountability." \
            'Set:  PermitRootLogin no' "$FIRST_PATH"
    fi

    # PasswordAuthentication
    get_dir 'PasswordAuthentication'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" == 'yes' ]]; then
        add openssh HIGH 'Password authentication enabled' \
            'Password-based logins are vulnerable to brute-force and credential-stuffing attacks.' \
            'Set:  PasswordAuthentication no  (use SSH key pairs instead)' "$FIRST_PATH"
    fi

    # PermitEmptyPasswords
    get_dir 'PermitEmptyPasswords'; v="${_VAL,,}"
    if [[ "$v" == 'yes' ]]; then
        add openssh CRITICAL 'Empty passwords permitted' \
            '"PermitEmptyPasswords yes" — accounts with no password can log in over SSH.' \
            'Set:  PermitEmptyPasswords no' "$FIRST_PATH"
    fi

    # Protocol (legacy sshd_config directive)
    get_dir 'Protocol'; v="${_VAL:-}"
    if [[ -n "$v" && "$v" == *'1'* ]]; then
        add openssh CRITICAL 'SSHv1 protocol enabled' \
            "Protocol = \"$v\" — SSHv1 has fundamental cryptographic flaws and must not be used." \
            'Set:  Protocol 2' "$FIRST_PATH"
    fi

    # X11Forwarding
    get_dir 'X11Forwarding'; v="${_VAL,,}"
    if [[ "$v" == 'yes' ]]; then
        add openssh MEDIUM 'X11 forwarding enabled' \
            'X11Forwarding yes can be exploited to hijack graphical sessions or bypass network restrictions.' \
            'Set:  X11Forwarding no  (unless explicitly required by your users)' "$FIRST_PATH"
    fi

    # MaxAuthTries
    get_dir 'MaxAuthTries'; v="${_VAL:-6}"
    if ! [[ "$v" =~ ^[0-9]+$ ]] || (( v > 4 )); then
        add openssh MEDIUM 'MaxAuthTries too high' \
            "MaxAuthTries = \"${_VAL:-6 (default)}\" — too many failed attempts allowed before disconnect, aiding brute-force." \
            'Set:  MaxAuthTries 3' "$FIRST_PATH"
    fi

    # LoginGraceTime
    get_dir 'LoginGraceTime'; v="${_VAL:-120}"
    local grace="${v//s/}"  # strip trailing 's'
    if [[ "$grace" =~ ^[0-9]+$ ]] && (( grace > 60 )); then
        add openssh LOW 'LoginGraceTime too long' \
            "LoginGraceTime = ${_VAL:-120s (default)} — unauthenticated connections held open too long." \
            'Set:  LoginGraceTime 30' "$FIRST_PATH"
    fi

    # AllowUsers / AllowGroups
    if ! body_has '^[[:space:]]*(AllowUsers|AllowGroups)[[:space:]]+'; then
        add openssh MEDIUM 'No AllowUsers or AllowGroups configured' \
            'Any valid system account can attempt to authenticate — the SSH attack surface is unnecessarily wide.' \
            'Add:  AllowUsers <user1> <user2>  (or AllowGroups <group>)' "$FIRST_PATH"
    fi

    # ClientAliveInterval
    get_dir 'ClientAliveInterval'; v="${_VAL:-0}"
    if [[ "$v" == '0' || -z "${_VAL:-}" ]]; then
        add openssh LOW 'Idle session timeout not configured' \
            'ClientAliveInterval = 0 (or unset) — idle SSH sessions never time out, leaving abandoned connections open.' \
            $'Set:\n  ClientAliveInterval 300\n  ClientAliveCountMax 3' "$FIRST_PATH"
    fi

    # Banner
    get_dir 'Banner'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" == 'none' ]]; then
        add openssh LOW 'No SSH login banner configured' \
            'A login banner provides legal notice to unauthorised users and can support any prosecution.' \
            'Set:  Banner /etc/ssh/banner  (populate the file with an appropriate legal warning)' "$FIRST_PATH"
    fi

    # UseDNS
    get_dir 'UseDNS'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" == 'yes' ]]; then
        add openssh LOW 'UseDNS enabled (reverse-DNS lookups per connection)' \
            'UseDNS yes causes a reverse-DNS lookup for every connection. Results can be spoofed and add latency.' \
            'Set:  UseDNS no' "$FIRST_PATH"
    fi

    # Weak ciphers
    get_dir 'Ciphers'; v="${_VAL,,}"
    if [[ -n "$v" ]]; then
        local c
        for c in 'arcfour' '3des-cbc' 'blowfish-cbc' 'cast128-cbc' \
                 'aes128-cbc' 'aes192-cbc' 'aes256-cbc'; do
            if [[ "$v" == *"$c"* ]]; then
                add openssh HIGH 'Weak ciphers permitted in Ciphers directive' \
                    "The Ciphers list includes \"$c\" (and possibly others) — CBC-mode ciphers have known vulnerabilities." \
                    'Set:  Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com' "$FIRST_PATH"
                break
            fi
        done
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# vsftpd
# ─────────────────────────────────────────────────────────────────────────────

check_vsftpd() {
    load_configs '/etc/vsftpd.conf' '/etc/vsftpd/vsftpd.conf' || {
        add vsftpd INFO 'Config not found' \
            'vsftpd.conf not found. Ensure vsftpd is installed.' \
            'Ubuntu: apt install vsftpd  |  Rocky: dnf install vsftpd' ''
        return
    }

    local v

    # anonymous_enable
    get_eq 'anonymous_enable'; v="${_VAL^^}"
    if [[ -z "$v" || "$v" == 'YES' ]]; then
        add vsftpd CRITICAL 'Anonymous FTP access enabled' \
            "anonymous_enable = \"${_VAL:-YES (default in some builds)}\" — unauthenticated access to the FTP server is permitted." \
            'Set:  anonymous_enable=NO' "$FIRST_PATH"
    fi

    # anon_upload_enable
    get_eq 'anon_upload_enable'; v="${_VAL^^}"
    if [[ "$v" == 'YES' ]]; then
        add vsftpd CRITICAL 'Anonymous uploads enabled' \
            '"anon_upload_enable=YES" — anonymous users can upload arbitrary files to the server.' \
            'Set:  anon_upload_enable=NO' "$FIRST_PATH"
    fi

    # anon_mkdir_write_enable
    get_eq 'anon_mkdir_write_enable'; v="${_VAL^^}"
    if [[ "$v" == 'YES' ]]; then
        add vsftpd HIGH 'Anonymous directory creation enabled' \
            '"anon_mkdir_write_enable=YES" — anonymous users can create directories on the server.' \
            'Set:  anon_mkdir_write_enable=NO' "$FIRST_PATH"
    fi

    # chroot_local_user
    get_eq 'chroot_local_user'; v="${_VAL^^}"
    if [[ -z "$v" || "$v" != 'YES' ]]; then
        add vsftpd HIGH 'Local users not chrooted to home directory' \
            'Without chroot_local_user=YES, authenticated users can navigate the entire server filesystem.' \
            'Set:  chroot_local_user=YES' "$FIRST_PATH"
    fi

    # ssl_enable
    get_eq 'ssl_enable'; v="${_VAL^^}"
    if [[ -z "$v" || "$v" != 'YES' ]]; then
        add vsftpd HIGH 'SSL/TLS not enabled' \
            'FTP credentials (username + password) and all file data are transmitted in cleartext.' \
            'Set:  ssl_enable=YES  and configure rsa_cert_file / rsa_private_key_file' "$FIRST_PATH"
    else
        # allow_anon_ssl
        get_eq 'allow_anon_ssl'; v="${_VAL^^}"
        if [[ "$v" == 'YES' ]]; then
            add vsftpd MEDIUM 'SSL allowed for anonymous sessions' \
                '"allow_anon_ssl=YES" — anonymous users can establish SSL sessions.' \
                'Set:  allow_anon_ssl=NO' "$FIRST_PATH"
        fi

        # force_local_data_ssl / force_local_logins_ssl
        local directive
        for directive in 'force_local_data_ssl' 'force_local_logins_ssl'; do
            get_eq "$directive"; v="${_VAL^^}"
            if [[ -z "$v" || "$v" != 'YES' ]]; then
                add vsftpd MEDIUM "${directive} not enforced" \
                    "SSL is enabled but ${directive} is not YES — plaintext fallback sessions may still be accepted." \
                    "Set:  ${directive}=YES" "$FIRST_PATH"
            fi
        done
    fi

    # xferlog_enable
    get_eq 'xferlog_enable'; v="${_VAL^^}"
    if [[ -z "$v" || "$v" != 'YES' ]]; then
        add vsftpd LOW 'File transfer logging disabled' \
            '"xferlog_enable" is not YES — FTP transfers are not logged, leaving no audit trail.' \
            'Set:  xferlog_enable=YES' "$FIRST_PATH"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Samba
# ─────────────────────────────────────────────────────────────────────────────

# Extract a value from the [global] section of smb.conf only.
# Uses global $BODY. Result in $_VAL.
get_global_smb() {
    _VAL=""
    local key="${1,,}"
    _VAL=$(printf '%s\n' "$BODY" | awk -v key="$key" '
        /^\[global\]/                   { in_g=1; next }
        /^\[[^]]+\]/ && !/^\[global\]/  { in_g=0 }
        in_g {
            line = tolower($0)
            gsub(/^[[:space:]]+/, "", line)
            if (line ~ ("^" key "[[:space:]]*=")) {
                sub(/^[^=]+=[[:space:]]*/, "", line)
                sub(/[[:space:]]*#.*$/, "", line)
                print line; exit
            }
        }
    ') || true
}

check_samba() {
    load_configs '/etc/samba/smb.conf' '/etc/smb.conf' || {
        add samba INFO 'Config not found' \
            'smb.conf not found. Ensure Samba is installed.' \
            'Ubuntu: apt install samba  |  Rocky: dnf install samba' ''
        return
    }

    local v

    # null passwords
    get_global_smb 'null passwords'; v="${_VAL,,}"
    if [[ "$v" == 'yes' || "$v" == 'true' || "$v" == '1' ]]; then
        add samba CRITICAL 'Null passwords allowed' \
            '"null passwords = yes" in [global] — accounts with no password can authenticate to any share.' \
            'Set:  null passwords = no' "$FIRST_PATH"
    fi

    # guest ok
    if body_has '^[[:space:]]*guest ok[[:space:]]*=[[:space:]]*yes'; then
        add samba HIGH 'Guest access enabled on one or more shares' \
            '"guest ok = yes" is present — unauthenticated users can access those shares.' \
            'Set "guest ok = no" on all shares. Restrict guest access carefully only where required.' "$FIRST_PATH"
    fi

    # map to guest
    get_global_smb 'map to guest'; v="${_VAL,,}"
    if [[ "$v" == 'bad user' || "$v" == 'bad password' ]]; then
        add samba HIGH 'map to guest allows unauthenticated fallback' \
            "\"map to guest = ${_VAL}\" — failed logins fall back to a guest session instead of being rejected." \
            'Set:  map to guest = never' "$FIRST_PATH"
    fi

    # server signing
    get_global_smb 'server signing'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" == 'auto' || "$v" == 'disabled' || "$v" == 'no' ]]; then
        add samba HIGH 'SMB signing not mandatory' \
            "server signing = \"${_VAL:-auto (default)}\" — SMB packets can be tampered with via man-in-the-middle attacks." \
            'Set:  server signing = mandatory' "$FIRST_PATH"
    fi

    # smb encrypt
    get_global_smb 'smb encrypt'; v="${_VAL,,}"
    if [[ -z "$v" || "$v" == 'auto' || "$v" == 'disabled' || "$v" == 'no' ]]; then
        add samba MEDIUM 'SMB encryption not required' \
            "smb encrypt = \"${_VAL:-auto (default)}\" — SMB traffic is not encrypted end-to-end." \
            'Set:  smb encrypt = required  (Samba 4.x+)' "$FIRST_PATH"
    fi

    # restrict anonymous
    get_global_smb 'restrict anonymous'; v="${_VAL:-0}"
    if [[ -z "${_VAL:-}" || "$v" == '0' ]]; then
        add samba MEDIUM 'Anonymous enumeration not restricted' \
            "restrict anonymous = ${v} (default) — unauthenticated clients can enumerate shares and local users." \
            'Set:  restrict anonymous = 2' "$FIRST_PATH"
    fi

    # SMBv1 — min protocol settings
    local key
    for key in 'client min protocol' 'server min protocol'; do
        get_global_smb "$key"; v="${_VAL^^}"
        if [[ -z "$v" || "$v" == 'NT1' || "$v" == 'LANMAN1' || \
              "$v" == 'LANMAN2' || "$v" == 'CORE' || "$v" == 'COREPLUS' ]]; then
            add samba HIGH "SMBv1 may be permitted: ${key}" \
                "\"${key} = ${_VAL:-not set (may default to NT1)}\" — SMBv1 has critical known vulnerabilities (e.g. EternalBlue/MS17-010)." \
                "Set:  ${key} = SMB2" "$FIRST_PATH"
        fi
    done

    # Log level
    get_global_smb 'log level'; v="${_VAL:-}"
    if [[ -z "$v" ]]; then
        add samba LOW 'No log level configured' \
            'Without a log level directive, authentication failures and share access events may not be logged.' \
            'Set:  log level = 1  in the [global] section' "$FIRST_PATH"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# BIND DNS
# ─────────────────────────────────────────────────────────────────────────────

check_bind() {
    load_configs \
        '/etc/bind/named.conf' \
        '/etc/bind/named.conf.options' \
        '/etc/named.conf' \
        '/etc/named/named.conf' \
        '/etc/named/named.conf.options' || {
        add bind INFO 'Config not found' \
            'No BIND named.conf found at standard paths.' \
            'Ubuntu: apt install bind9  |  Rocky: dnf install bind' ''
        return
    }

    # Version disclosure
    if ! body_has 'version[[:space:]]+"[^"]+"'; then
        add bind MEDIUM 'BIND version not hidden' \
            'No "version" override is set — BIND reveals its true version via CHAOS TXT queries (dig CHAOS TXT version.bind @<host>).' \
            'Add inside the options { } block:  version "none";' "$FIRST_PATH"
    fi

    # Open recursion
    local recursion_on=0 recursion_set=0 allow_recursion=0
    body_has 'recursion[[:space:]]+yes[[:space:]]*;'   && recursion_on=1  || true
    body_has '^[[:space:]]*recursion[[:space:]]'       && recursion_set=1 || true
    body_has 'allow-recursion[[:space:]]*\{'           && allow_recursion=1 || true

    if (( recursion_on && ! allow_recursion )); then
        add bind CRITICAL 'Open recursive resolver (no allow-recursion)' \
            '"recursion yes" without allow-recursion — your server answers recursive queries for any internet host, enabling DNS amplification DDoS attacks.' \
            'Add:  allow-recursion { 127.0.0.1; <your_internal_networks>; };' "$FIRST_PATH"
    elif (( ! recursion_set )); then
        add bind MEDIUM 'recursion not explicitly configured' \
            'Default recursion behaviour depends on the BIND version and may permit open recursion.' \
            'Explicitly set "recursion yes;" + allow-recursion, or "recursion no;" for authoritative-only servers.' "$FIRST_PATH"
    fi

    # allow-query
    if ! body_has 'allow-query[[:space:]]*\{'; then
        add bind MEDIUM 'allow-query not configured' \
            'Without allow-query, BIND defaults to responding to queries from any source.' \
            'Set:  allow-query { your_network; };  (or { any; }; only if intentionally public)' "$FIRST_PATH"
    fi

    # allow-transfer
    if body_has 'allow-transfer[[:space:]]*\{[^}]*\bany\b[^}]*\}'; then
        add bind CRITICAL 'Zone transfers open to any host' \
            '"allow-transfer { any; }" — any internet host can request a full zone transfer, exposing every DNS record.' \
            'Restrict:  allow-transfer { <secondary_ns_IP>; };  or set { none; }; globally.' "$FIRST_PATH"
    elif ! body_has 'allow-transfer[[:space:]]*\{'; then
        add bind HIGH 'allow-transfer not configured' \
            'Zone transfers may default to open, leaking all DNS records to unauthenticated requesters.' \
            'Add globally:  allow-transfer { none; };  and permit only authorised secondary nameservers per-zone.' "$FIRST_PATH"
    fi

    # DNSSEC validation
    if ! body_has 'dnssec-validation[[:space:]]+(yes|auto)'; then
        add bind MEDIUM 'DNSSEC validation not enabled' \
            '"dnssec-validation" is not set to "yes" or "auto" — DNS responses are not cryptographically verified.' \
            'Add inside the options { } block:  dnssec-validation auto;' "$FIRST_PATH"
    fi

    # listen-on any
    if body_has 'listen-on[[:space:]]*\{[^}]*\bany\b[^}]*\}'; then
        add bind LOW 'BIND listening on all interfaces' \
            '"listen-on { any; }" may expose the DNS port on internal or management interfaces unnecessarily.' \
            'Restrict listen-on to specific IP addresses if BIND should not be publicly reachable.' "$FIRST_PATH"
    fi

    # Logging
    if ! body_has 'logging[[:space:]]*\{'; then
        add bind LOW 'No logging block configured' \
            'Without a logging block, DNS query logging is minimal — abuse and reconnaissance are harder to detect.' \
            'Add a "logging { channel ...; category ...; };" block to capture query logs.' "$FIRST_PATH"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PostgreSQL
# ─────────────────────────────────────────────────────────────────────────────

check_postgres() {
    local pg_body="" pg_path="" hba_body="" hba_path=""
    local f old_nullglob
    old_nullglob=$(shopt -p nullglob)
    shopt -s nullglob

    # postgresql.conf
    local pattern
    for pattern in \
        '/etc/postgresql/*/main/postgresql.conf' \
        '/var/lib/pgsql/data/postgresql.conf' \
        '/var/lib/postgresql/*/data/postgresql.conf'; do
        for f in $pattern; do
            [[ -f "$f" ]] || continue
            pg_body=$(cat "$f" 2>/dev/null) && pg_path="$f" && break 2
        done
    done

    # pg_hba.conf
    for pattern in \
        '/etc/postgresql/*/main/pg_hba.conf' \
        '/var/lib/pgsql/data/pg_hba.conf' \
        '/var/lib/postgresql/*/data/pg_hba.conf'; do
        for f in $pattern; do
            [[ -f "$f" ]] || continue
            hba_body=$(cat "$f" 2>/dev/null) && hba_path="$f" && break 2
        done
    done

    eval "$old_nullglob"

    if [[ -z "$pg_body" && -z "$hba_body" ]]; then
        add postgres INFO 'Config not found' \
            'No PostgreSQL config files found at standard paths.' \
            'Ubuntu: apt install postgresql  |  Rocky: dnf install postgresql-server' ''
        return
    fi

    local v

    # ── postgresql.conf ──────────────────────────────────────────────────────
    if [[ -n "$pg_body" ]]; then
        BODY="$pg_body"; FIRST_PATH="$pg_path"

        # listen_addresses
        get_eq 'listen_addresses'; v="$_VAL"
        if [[ "$v" == '*' ]]; then
            add postgres HIGH "PostgreSQL listening on all interfaces (listen_addresses = '*')" \
                "listen_addresses = '*' — the database port is exposed on every network interface." \
                "Set:  listen_addresses = 'localhost'  (use SSH tunnel or pgBouncer for remote access)" "$pg_path"
        fi

        # ssl
        get_eq 'ssl'; v="${_VAL,,}"
        if [[ -z "$v" || "$v" =~ ^(off|false|0|no)$ ]]; then
            add postgres HIGH 'SSL/TLS disabled' \
                "ssl = ${_VAL:-off} — client connections carry credentials and data in cleartext." \
                'Set:  ssl = on  and configure ssl_cert_file / ssl_key_file' "$pg_path"
        fi

        # password_encryption
        get_eq 'password_encryption'; v="${_VAL,,}"
        if [[ "$v" == 'md5' ]]; then
            add postgres MEDIUM 'Weak password hashing: MD5' \
                '"password_encryption = md5" — MD5 is cryptographically broken and susceptible to offline cracking.' \
                "Set:  password_encryption = 'scram-sha-256'" "$pg_path"
        fi

        # log_connections / log_disconnections
        local directive
        for directive in 'log_connections' 'log_disconnections'; do
            get_eq "$directive"; v="${_VAL,,}"
            if [[ -z "$v" || "$v" =~ ^(off|false|0|no)$ ]]; then
                add postgres LOW "${directive} not enabled" \
                    "${directive} = off — connection events are not logged; the audit trail is incomplete." \
                    "Set:  ${directive} = on" "$pg_path"
            fi
        done

        # log_hostname
        get_eq 'log_hostname'; v="${_VAL,,}"
        if [[ "$v" =~ ^(on|true|1|yes)$ ]]; then
            add postgres LOW 'log_hostname adds reverse-DNS lookup per connection' \
                '"log_hostname = on" resolves hostnames for every connection, adding latency and DNS dependency.' \
                'Set:  log_hostname = off  (unless hostname resolution in logs is specifically required)' "$pg_path"
        fi
    fi

    # ── pg_hba.conf ──────────────────────────────────────────────────────────
    if [[ -n "$hba_body" ]]; then
        BODY="$hba_body"; FIRST_PATH="$hba_path"
        local trust_lines=() md5_lines=()
        local line parts method conn_type db user

        while IFS= read -r line; do
            line="${line%%#*}"          # strip inline comments
            [[ -z "${line//[[:space:]]/}" ]] && continue
            read -ra parts <<< "$line"
            [[ ${#parts[@]} -lt 4 ]] && continue
            method="${parts[-1],,}"
            [[ "$method" == 'trust' ]] && trust_lines+=("$line")
            [[ "$method" == 'md5'   ]] && md5_lines+=("$line")
        done < <(printf '%s\n' "$hba_body")

        # trust auth
        if (( ${#trust_lines[@]} > 0 )); then
            local trust_all=0 tl
            for tl in "${trust_lines[@]}"; do
                [[ "$tl" == *'all'* ]] && trust_all=1 && break
            done
            local tsev; (( trust_all )) && tsev=CRITICAL || tsev=HIGH
            local tdesc="The following pg_hba.conf entries allow login with no password (trust):"
            for tl in "${trust_lines[@]}"; do tdesc+=$'\n  '"$tl"; done
            add postgres "$tsev" 'Trust authentication in pg_hba.conf (no password required)' \
                "$tdesc" \
                'Replace "trust" with "scram-sha-256". Trust should only exist on local socket entries for initial admin bootstrap.' "$hba_path"
        fi

        # md5 auth
        if (( ${#md5_lines[@]} > 0 )); then
            add postgres MEDIUM "MD5 authentication in pg_hba.conf (${#md5_lines[@]} entry/entries)" \
                'MD5 password auth is present — MD5 is deprecated and weak against offline cracking attacks.' \
                'Upgrade to "scram-sha-256" and set password_encryption = scram-sha-256 in postgresql.conf.' "$hba_path"
        fi

        # Broad remote-access rule for superuser / all users
        while IFS= read -r line; do
            line="${line%%#*}"
            [[ -z "${line//[[:space:]]/}" ]] && continue
            read -ra parts <<< "$line"
            [[ ${#parts[@]} -lt 4 ]] && continue
            conn_type="${parts[0],,}"; db="${parts[1],,}"; user="${parts[2],,}"
            if [[ "$conn_type" == 'host' && "$db" == 'all' && \
                  ( "$user" == 'all' || "$user" == 'postgres' ) ]]; then
                add postgres HIGH 'Broad remote-access rule in pg_hba.conf' \
                    "The entry \"$line\" grants remote access for user \"${parts[2]}\" to all databases." \
                    'Restrict pg_hba.conf entries to specific users, databases, and IP ranges. Superuser should only connect locally.' "$hba_path"
                break
            fi
        done < <(printf '%s\n' "$hba_body")
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Report rendering
# ─────────────────────────────────────────────────────────────────────────────

SEP80='================================================================================'
SEP78='--------------------------------------------------------------------------------'

make_bar() {   # make_bar <count>  →  prints █ chars (capped at 40)
    local n="${1:-0}" i bar=""
    local max=$(( n > 40 ? 40 : n ))
    for (( i=0; i<max; i++ )); do bar+='█'; done
    printf '%s' "$bar"
}

print_header() {
    printf '\n%s\n' "$SEP80"
    printf '  SECURITY CONFIGURATION SCAN REPORT\n'
    printf '  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf '  Services: %s\n' "$*"
    printf '%s\n\n' "$SEP80"
}

print_summary() {
    local sev n bar
    declare -A _counts=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0 [INFO]=0)
    local i
    for (( i=0; i<F_N; i++ )); do
        (( _counts[${F_SEV[$i]}]++ )) || true
    done

    printf '  SUMMARY\n\n'
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        n="${_counts[$sev]}"
        (( n == 0 )) && continue
        bar=$(make_bar "$n")
        printf '  %-9s  %s  %d\n' "$sev" "$bar" "$n"
    done

    local actionable=0
    for sev in CRITICAL HIGH MEDIUM LOW; do
        (( actionable += _counts[$sev] )) || true
    done
    printf '\n  Actionable findings: %d\n\n' "$actionable"
    printf '%s\n' "$SEP78"
    unset _counts
}

print_service_block() {
    local service="$1"
    printf '\n  >> %s\n' "${service^^}"
    printf '%s\n' "$SEP78"

    local i sev num=0 first_line line
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        for (( i=0; i<F_N; i++ )); do
            [[ "${F_SVC[$i]}" == "$service" && "${F_SEV[$i]}" == "$sev" ]] || continue
            passes_filter "$sev" || continue
            (( num++ ))

            printf '\n  %d. [%s] %s\n' "$num" "$sev" "${F_TITLE[$i]}"

            [[ -n "${F_PATH[$i]}" ]] && printf '     File:  %s\n' "${F_PATH[$i]}"

            # Multi-line description
            first_line=1
            while IFS= read -r line; do
                if (( first_line )); then
                    printf '     Issue: %s\n' "$line"
                    first_line=0
                else
                    printf '            %s\n' "$line"
                fi
            done <<< "${F_DESC[$i]}"

            # Multi-line fix
            first_line=1
            while IFS= read -r line; do
                if (( first_line )); then
                    printf '     Fix:   %s\n' "$line"
                    first_line=0
                else
                    printf '            %s\n' "$line"
                fi
            done <<< "${F_FIX[$i]}"
        done
    done

    if (( num == 0 )); then
        printf '\n  No findings match the current filter.\n'
    fi
    printf '\n'
}

render_report() {
    print_header "$@"
    print_summary
    local svc
    for svc in "$@"; do
        print_service_block "$svc"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Service registry
# ─────────────────────────────────────────────────────────────────────────────

ALL_SERVICES=(apache2 nginx openssh vsftpd samba bind postgres)

declare -A ALIASES=(
    [apache]=apache2   [httpd]=apache2
    [ssh]=openssh      [sshd]=openssh
    [ftp]=vsftpd
    [smb]=samba
    [dns]=bind         [named]=bind
    [postgresql]=postgres  [pgsql]=postgres
)

# ─────────────────────────────────────────────────────────────────────────────
# Usage
# ─────────────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $(basename "$0") -s <service> [service…] [options]

Options:
  -s, --services <svc…>   Services to scan (required). Use "all" for every service.
  -o, --output <file>     Write a plain-text copy of the report to this file.
      --severity <level>  Only show findings at or above this level.
                          Levels: CRITICAL  HIGH  MEDIUM  LOW  INFO
  -h, --help              Show this message.

Supported services (aliases accepted):
  apache2  (apache, httpd)   nginx    openssh  (ssh, sshd)
  vsftpd   (ftp)             samba    (smb)    bind  (dns, named)
  postgres (postgresql, pgsql)
  all — scan every service listed above

Examples:
  $(basename "$0") -s openssh nginx postgres
  $(basename "$0") -s all -o /tmp/report.txt
  $(basename "$0") -s all --severity HIGH
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

SERVICES=()
OUTPUT_FILE=""

if [[ $# -eq 0 ]]; then
    usage; exit 1
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--services)
            shift
            while [[ $# -gt 0 && "$1" != -* ]]; do
                SERVICES+=("$1"); shift
            done
            ;;
        -o|--output)
            shift; OUTPUT_FILE="$1"; shift ;;
        --severity)
            shift; SEVERITY_FILTER="${1^^}"; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            printf 'Unknown option: %s\n\n' "$1" >&2
            usage >&2; exit 1 ;;
    esac
done

if (( ${#SERVICES[@]} == 0 )); then
    printf 'Error: --services (-s) is required.\n\n' >&2
    usage >&2; exit 1
fi

# Validate severity filter
if [[ -n "$SEVERITY_FILTER" ]]; then
    case "$SEVERITY_FILTER" in
        CRITICAL|HIGH|MEDIUM|LOW|INFO) ;;
        *)
            printf 'Error: invalid severity "%s".\nValid levels: CRITICAL HIGH MEDIUM LOW INFO\n' \
                "$SEVERITY_FILTER" >&2
            exit 1 ;;
    esac
fi

# Disable colour when not writing to a terminal, or when explicitly requested
# ─────────────────────────────────────────────────────────────────────────────
# Resolve and deduplicate requested service names
# ─────────────────────────────────────────────────────────────────────────────

RESOLVED=()
for svc in "${SERVICES[@]}"; do
    svc_lower="${svc,,}"
    if [[ "$svc_lower" == 'all' ]]; then
        for s in "${ALL_SERVICES[@]}"; do
            local_found=0
            for r in "${RESOLVED[@]:-}"; do [[ "$r" == "$s" ]] && local_found=1; done
            (( local_found )) || RESOLVED+=("$s")
        done
        continue
    fi

    if [[ -v ALIASES[$svc_lower] ]]; then
        resolved="${ALIASES[$svc_lower]}"
    else
        resolved="$svc_lower"
    fi

    # Validate
    valid=0
    for s in "${ALL_SERVICES[@]}"; do [[ "$s" == "$resolved" ]] && valid=1; done
    if (( ! valid )); then
        printf 'Warning: unknown service "%s" — skipping.\n' "$svc" >&2
        continue
    fi

    # Deduplicate
    local_found=0
    for r in "${RESOLVED[@]:-}"; do [[ "$r" == "$resolved" ]] && local_found=1; done
    (( local_found )) || RESOLVED+=("$resolved")
done

if (( ${#RESOLVED[@]} == 0 )); then
    printf 'Error: no valid services specified.\n' >&2; exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# Run checks
# ─────────────────────────────────────────────────────────────────────────────

for svc in "${RESOLVED[@]}"; do
    printf 'Scanning %s...\n' "$svc" >&2
    "check_${svc}"
done

# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

render_report "${RESOLVED[@]}"

if [[ -n "$OUTPUT_FILE" ]]; then
    render_report "${RESOLVED[@]}" > "$OUTPUT_FILE"
    printf '\nReport written to: %s\n' "$OUTPUT_FILE" >&2
fi