#!/bin/bash
# find backdoors on services

BODY=""; _VAL=""; COUNT_CRIT=0; COUNT_HIGH=0; COUNT_MED=0

load_configs() {
    BODY=""
    local f pat found=1
    shopt -s nullglob
    for pat in "$@"; do
        for f in $pat; do
            [[ -f $f ]] || continue
            BODY+=$'\n'"$(cat "$f" 2>/dev/null)"
            found=0
        done
    done
    shopt -u nullglob
    return $found
}

get_dir() {
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*$1[[:space:]]+" | grep -v '^[[:space:]]*#' | head -1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]+//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

get_eq() {
    _VAL=$(printf '%s\n' "$BODY" \
        | grep -iE "^[[:space:]]*$1[[:space:]]*=" | grep -v '^[[:space:]]*#' | head -1 \
        | sed -E "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//i; s/[[:space:]]*#.*//; s/['\"]//g" \
        | xargs 2>/dev/null) || true
}

body_has() { printf '%s\n' "$BODY" | grep -qiE "$1"; }

hit() {
    printf '  [%-8s] %s\n             fix: %s\n' "$1" "$2" "$3"
    case "$1" in CRITICAL) COUNT_CRIT=$((COUNT_CRIT+1)) ;;
                 HIGH)     COUNT_HIGH=$((COUNT_HIGH+1)) ;;
                 MEDIUM)   COUNT_MED=$((COUNT_MED+1))  ;; esac
}

# apache2 web server
check_apache2() {
    load_configs \
        '/etc/apache2/apache2.conf' '/etc/apache2/conf-enabled/*.conf' \
        '/etc/apache2/sites-enabled/*.conf' '/etc/httpd/conf/httpd.conf' \
        '/etc/httpd/conf.d/*.conf' || { echo "  (not installed)"; return; }
    local proto clean

    # Directory listing - exposes files/backups/creds in docroot
    body_has 'Options[[:space:]][^#]*\bIndexes\b' && \
        hit HIGH 'Directory listing enabled (Options Indexes)' \
            'remove "Indexes" from all Options directives'

    # FollowSymLinks without SymLinksIfOwnerMatch - docroot escape
    if body_has 'Options[[:space:]][^#]*\bFollowSymLinks\b' && \
       ! body_has 'Options[[:space:]][^#]*\bSymLinksIfOwnerMatch\b'; then
        hit MEDIUM 'FollowSymLinks without SymLinksIfOwnerMatch (docroot escape risk)' \
            'replace FollowSymLinks with SymLinksIfOwnerMatch'
    fi

    # AllowOverride All - .htaccess can override security directives
    body_has '^[[:space:]]*AllowOverride[[:space:]]+All\b' && \
        hit MEDIUM 'AllowOverride All - .htaccess can override security rules' \
            'AllowOverride None  (or only the directives you need)'

    # TRACE method - XST cookie theft
    get_dir TraceEnable
    [[ -z $_VAL || ${_VAL,,} != off ]] && \
        hit MEDIUM 'HTTP TRACE enabled (XST cookie theft)' \
            'TraceEnable Off'

    # Weak TLS protocols - downgrade
    for proto in SSLv2 SSLv3 'TLSv1 ' 'TLSv1\.1'; do
        body_has "SSLProtocol[[:space:]][^#]*${proto}" || continue
        clean="${proto// /}"
        hit HIGH "Weak TLS protocol permitted: $clean" \
            'SSLProtocol TLSv1.2 TLSv1.3'
    done

    # /server-status without IP restriction - internals/URIs exposed
    if body_has '<Location[[:space:]][^>]*/server-status' && \
       ! body_has 'Require[[:space:]]+(ip|local|host)'; then
        hit HIGH '/server-status exposed without IP restriction' \
            'add "Require ip 127.0.0.1" inside the <Location /server-status>'
    fi
}

# nginx web server/proxy
check_nginx() {
    load_configs \
        '/etc/nginx/nginx.conf' '/etc/nginx/conf.d/*.conf' \
        '/etc/nginx/sites-enabled/*.conf' || { echo "  (not installed)"; return; }
    local proto_line proto clean

    # autoindex on - directory listing
    body_has '^[[:space:]]*autoindex[[:space:]]+on[[:space:]]*;' && \
        hit HIGH 'Directory listing enabled (autoindex on)' \
            'autoindex off;'

    # Weak SSL protocols
    proto_line=$(printf '%s\n' "$BODY" | grep -iE 'ssl_protocols[[:space:]]+' | head -1)
    if [[ -n $proto_line ]]; then
        for proto in SSLv2 SSLv3 'TLSv1 ' 'TLSv1\.1'; do
            printf '%s\n' "$proto_line" | grep -qiE "$proto" || continue
            clean="${proto// /}"
            hit HIGH "Weak TLS protocol in ssl_protocols: $clean" \
                'ssl_protocols TLSv1.2 TLSv1.3;'
        done
    fi
}

# openssh ssh server
check_openssh() {
    load_configs '/etc/ssh/sshd_config' '/etc/ssh/sshd_config.d/*.conf' \
        || { echo "  (not installed)"; return; }
    local v c

    # Root login
    get_dir PermitRootLogin; v="${_VAL,,}"
    [[ -z $v || ( $v != no && $v != prohibit-password && $v != forced-commands-only ) ]] && \
        hit CRITICAL "Root SSH login permitted (PermitRootLogin=${_VAL:-yes})" \
            'PermitRootLogin no'

    # Empty passwords
    get_dir PermitEmptyPasswords
    [[ ${_VAL,,} == yes ]] && \
        hit CRITICAL 'Empty passwords permitted over SSH' \
            'PermitEmptyPasswords no'

    # Protocol 1
    get_dir Protocol
    [[ -n $_VAL && $_VAL == *1* ]] && \
        hit CRITICAL "SSHv1 enabled (Protocol=$_VAL)" \
            'Protocol 2'

    # Password auth (brute force surface)
    get_dir PasswordAuthentication; v="${_VAL,,}"
    [[ -z $v || $v == yes ]] && \
        hit HIGH 'Password authentication enabled (brute-force exposure)' \
            'PasswordAuthentication no  (deploy SSH keys)'

    # MaxAuthTries (brute force aid)
    get_dir MaxAuthTries; v="${_VAL:-6}"
    if ! [[ $v =~ ^[0-9]+$ ]] || (( v > 4 )); then
        hit MEDIUM "MaxAuthTries=${_VAL:-6} - too many attempts per connection" \
            'MaxAuthTries 3'
    fi

    # Weak Ciphers
    get_dir Ciphers; v="${_VAL,,}"
    if [[ -n $v ]]; then
        for c in arcfour 3des-cbc blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc; do
            [[ $v == *"$c"* ]] || continue
            hit HIGH "Weak cipher in SSH Ciphers list: $c" \
                'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com'
            break
        done
    fi

    # AllowUsers/AllowGroups (reduces attack surface)
    body_has '^[[:space:]]*(AllowUsers|AllowGroups)[[:space:]]+' || \
        hit MEDIUM 'No AllowUsers/AllowGroups - every system account can authenticate' \
            'AllowUsers <user1> <user2>'

	# Backdoored AuthorizedKeysFile
    get_dir AuthorizedKeysFile
    # Default is usually .ssh/authorized_keys or .ssh/authorized_keys .ssh/authorized_keys2
    if [[ -n $_VAL && $_VAL != ".ssh/authorized_keys" && $_VAL != ".ssh/authorized_keys .ssh/authorized_keys2" ]]; then
        hit CRITICAL "Non-standard AuthorizedKeysFile defined: $_VAL" \
            'Remove AuthorizedKeysFile directive to restore default behavior'
    fi
}

# vsftpd ftp server
check_vsftpd() {
    load_configs '/etc/vsftpd.conf' '/etc/vsftpd/vsftpd.conf' \
        || { echo "  (not installed)"; return; }
    local v d

    # Anonymous access
    get_eq anonymous_enable; v="${_VAL^^}"
    [[ -z $v || $v == YES ]] && \
        hit CRITICAL "Anonymous FTP enabled (anonymous_enable=${_VAL:-YES})" \
            'anonymous_enable=NO'

    # Anonymous upload - webshell drop
    get_eq anon_upload_enable
    [[ ${_VAL^^} == YES ]] && \
        hit CRITICAL 'Anonymous uploads enabled (webshell drop vector)' \
            'anon_upload_enable=NO'

    get_eq anon_mkdir_write_enable
    [[ ${_VAL^^} == YES ]] && \
        hit HIGH 'Anonymous directory creation enabled' \
            'anon_mkdir_write_enable=NO'

    # Local users not chrooted - filesystem traversal
    get_eq chroot_local_user; v="${_VAL^^}"
    [[ -z $v || $v != YES ]] && \
        hit HIGH 'Local users not chrooted - full FS traversal via FTP' \
            'chroot_local_user=YES'

    # Cleartext credentials
    get_eq ssl_enable; v="${_VAL^^}"
    if [[ -z $v || $v != YES ]]; then
        hit HIGH 'SSL/TLS disabled - FTP creds+data in cleartext' \
            'ssl_enable=YES + rsa_cert_file/rsa_private_key_file'
    else
        get_eq allow_anon_ssl
        [[ ${_VAL^^} == YES ]] && \
            hit MEDIUM 'allow_anon_ssl=YES - SSL for anonymous sessions' \
                'allow_anon_ssl=NO'
        for d in force_local_data_ssl force_local_logins_ssl; do
            get_eq "$d"; v="${_VAL^^}"
            [[ -z $v || $v != YES ]] && \
                hit MEDIUM "$d not enforced - plaintext fallback" "$d=YES"
        done
    fi
}

# samba smb server
get_global_smb() {
    _VAL=$(printf '%s\n' "$BODY" | awk -v key="${1,,}" '
        /^\[global\]/                   { in_g=1; next }
        /^\[[^]]+\]/ && !/^\[global\]/  { in_g=0 }
        in_g {
            line = tolower($0); gsub(/^[[:space:]]+/, "", line)
            if (line ~ ("^" key "[[:space:]]*=")) {
                sub(/^[^=]+=[[:space:]]*/, "", line); sub(/[[:space:]]*#.*$/, "", line)
                print line; exit
            }
        }') || true
}

check_samba() {
    load_configs '/etc/samba/smb.conf' '/etc/smb.conf' \
        || { echo "  (not installed)"; return; }
    local v key

    # Null passwords
    get_global_smb 'null passwords'; v="${_VAL,,}"
    [[ $v == yes || $v == true || $v == 1 ]] && \
        hit CRITICAL 'null passwords = yes - empty-password accounts accepted' \
            'null passwords = no'

    # Guest access
    body_has '^[[:space:]]*guest ok[[:space:]]*=[[:space:]]*yes' && \
        hit HIGH 'guest ok = yes on one or more shares - unauthenticated share access' \
            'guest ok = no  (on every share)'

    get_global_smb 'map to guest'; v="${_VAL,,}"
    [[ $v == 'bad user' || $v == 'bad password' ]] && \
        hit HIGH "map to guest = $_VAL - failed logins fall back to guest" \
            'map to guest = never'

    # SMB signing / MITM
    get_global_smb 'server signing'; v="${_VAL,,}"
    [[ -z $v || $v == auto || $v == disabled || $v == no ]] && \
        hit HIGH "server signing=${_VAL:-auto} - SMB packets MITM-tamperable" \
            'server signing = mandatory'

    # SMBv1 / EternalBlue
    for key in 'client min protocol' 'server min protocol'; do
        get_global_smb "$key"; v="${_VAL^^}"
        [[ -z $v || $v == NT1 || $v == LANMAN1 || $v == LANMAN2 || $v == CORE || $v == COREPLUS ]] && \
            hit HIGH "$key=${_VAL:-unset} - SMBv1 (EternalBlue/MS17-010)" \
                "$key = SMB2"
    done

    # Encryption
    get_global_smb 'smb encrypt'; v="${_VAL,,}"
    [[ -z $v || $v == auto || $v == disabled || $v == no ]] && \
        hit MEDIUM "smb encrypt=${_VAL:-auto} - SMB traffic not end-to-end encrypted" \
            'smb encrypt = required'

    # Anonymous enumeration (share/user discovery)
    get_global_smb 'restrict anonymous'; v="${_VAL:-0}"
    [[ -z ${_VAL:-} || $v == 0 ]] && \
        hit MEDIUM 'Anonymous share/user enumeration allowed' \
            'restrict anonymous = 2'
}

# named dns server
check_bind() {
    load_configs \
        '/etc/bind/named.conf' '/etc/bind/named.conf.options' \
        '/etc/named.conf' '/etc/named/named.conf' '/etc/named/named.conf.options' \
        || { echo "  (not installed)"; return; }

    # Open recursion - amplification DDoS, cache poisoning
    if body_has 'recursion[[:space:]]+yes[[:space:]]*;' && \
       ! body_has 'allow-recursion[[:space:]]*\{'; then
        hit CRITICAL 'Open recursive resolver (recursion yes; no allow-recursion)' \
            'allow-recursion { 127.0.0.1; <internal>; };'
    fi

    # Zone transfer open - full zone dump
    if body_has 'allow-transfer[[:space:]]*\{[^}]*\bany\b[^}]*\}'; then
        hit CRITICAL 'Zone transfers open to any host (allow-transfer { any; })' \
            'allow-transfer { <secondary_ns_ip>; };'
    elif ! body_has 'allow-transfer[[:space:]]*\{'; then
        hit HIGH 'allow-transfer not configured - may default to open' \
            'allow-transfer { none; };  globally'
    fi

    # allow-query not set
    body_has 'allow-query[[:space:]]*\{' || \
        hit MEDIUM 'allow-query not configured - answers any source' \
            'allow-query { your_network; };'
}

# postgresql
check_postgres() {
    local pg_body="" pg_path="" hba_body="" hba_path="" f pat
    shopt -s nullglob
    for pat in '/etc/postgresql/*/main/postgresql.conf' \
               '/var/lib/pgsql/data/postgresql.conf' \
               '/var/lib/postgresql/*/data/postgresql.conf'; do
        for f in $pat; do [[ -f $f ]] && pg_body=$(cat "$f") && pg_path=$f && break 2; done
    done
    for pat in '/etc/postgresql/*/main/pg_hba.conf' \
               '/var/lib/pgsql/data/pg_hba.conf' \
               '/var/lib/postgresql/*/data/pg_hba.conf'; do
        for f in $pat; do [[ -f $f ]] && hba_body=$(cat "$f") && hba_path=$f && break 2; done
    done
    shopt -u nullglob

    [[ -z $pg_body && -z $hba_body ]] && { echo "  (not installed)"; return; }

    local v line parts method trust_lines=() md5_lines=() conn_type db user

    if [[ -n $pg_body ]]; then
        BODY="$pg_body"

        get_eq listen_addresses
        [[ $_VAL == '*' ]] && \
            hit HIGH "listen_addresses='*' - DB port exposed on every interface" \
                "listen_addresses = 'localhost'"

        get_eq ssl; v="${_VAL,,}"
        [[ -z $v || $v =~ ^(off|false|0|no)$ ]] && \
            hit HIGH "ssl=${_VAL:-off} - cleartext credentials+data" \
                'ssl = on + ssl_cert_file/ssl_key_file'

        get_eq password_encryption; v="${_VAL,,}"
        [[ $v == md5 ]] && \
            hit MEDIUM 'password_encryption = md5 (offline-crackable)' \
                "password_encryption = 'scram-sha-256'"
    fi

    if [[ -n $hba_body ]]; then
        BODY="$hba_body"

        while IFS= read -r line; do
            line="${line%%#*}"
            [[ -z ${line//[[:space:]]/} ]] && continue
            read -ra parts <<< "$line"
            (( ${#parts[@]} < 4 )) && continue
            method="${parts[-1],,}"
            [[ $method == trust ]] && trust_lines+=("$line")
            [[ $method == md5 ]]   && md5_lines+=("$line")
        done < <(printf '%s\n' "$hba_body")

        # trust auth
        if (( ${#trust_lines[@]} )); then
            local trust_all=0 tl
            for tl in "${trust_lines[@]}"; do [[ $tl == *all* ]] && trust_all=1 && break; done
            local tsev=HIGH; (( trust_all )) && tsev=CRITICAL
            hit "$tsev" "pg_hba.conf: ${#trust_lines[@]} trust entry/entries (no password required)" \
                'replace "trust" with "scram-sha-256"'
        fi

        # md5 auth
        (( ${#md5_lines[@]} )) && \
            hit MEDIUM "pg_hba.conf: ${#md5_lines[@]} md5 entry/entries (deprecated)" \
                'use scram-sha-256 + password_encryption=scram-sha-256'

        # Broad remote access rule - superuser / all users over network
        while IFS= read -r line; do
            line="${line%%#*}"
            [[ -z ${line//[[:space:]]/} ]] && continue
            read -ra parts <<< "$line"
            (( ${#parts[@]} < 4 )) && continue
            conn_type="${parts[0],,}"; db="${parts[1],,}"; user="${parts[2],,}"
            if [[ $conn_type == host && $db == all && \
                  ( $user == all || $user == postgres ) ]]; then
                hit HIGH "Broad remote rule in pg_hba.conf: ${parts[2]} to all DBs" \
                    'restrict to specific users/DBs/CIDRs; postgres superuser local-only'
                break
            fi
        done < <(printf '%s\n' "$hba_body")
    fi
}

# script starts running from here
ALL=(apache2 nginx openssh vsftpd samba bind postgres)

if (( $# == 0 )); then
    echo "usage: $0 <service|all> [service ...]"
    echo "services: ${ALL[*]}"
    exit 1
fi

SERVICES=()
for a in "$@"; do
    if [[ ${a,,} == all ]]; then SERVICES=("${ALL[@]}"); break; fi
    SERVICES+=("${a,,}")
done

printf '\n== fruit.sh - service config audit - %s ==\n' "$(date '+%F %T')"

for svc in "${SERVICES[@]}"; do
    fn="check_$svc"
    echo
    printf '>> %s\n' "$svc"
    if declare -f "$fn" >/dev/null; then
        "$fn"
    else
        echo "  unknown service (try: ${ALL[*]})"
    fi
done

echo
printf 'summary: %d critical / %d high / %d medium\n' \
    "$COUNT_CRIT" "$COUNT_HIGH" "$COUNT_MED"
