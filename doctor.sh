#!/bin/bash
# ==============================================================================
# Automated Linux Incident Response Expert System
# Supports: Ubuntu (Debian), Rocky Linux (RHEL)
# Services: Apache, Nginx, OpenSSH, vsftpd, Samba, BIND DNS, PostgreSQL
# ==============================================================================

# --- Formatting & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# --- Globals and OS Detection ---
OS_FLAVOR=""
APACHE_SVC="apache2"
DNS_SVC="bind9"
SSH_SVC="sshd"
SAMBA_SVC="smbd"

detect_os() {
    echo -e "${CYAN}[*] Detecting Operating System...${NC}"
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian)
                OS_FLAVOR="debian"
                APACHE_SVC="apache2"
                DNS_SVC="bind9"
                SSH_SVC="ssh"
                SAMBA_SVC="smbd"
                echo -e "${GREEN}[+] Detected Debian-based OS ($ID).${NC}"
                ;;
            rocky|rhel|centos|almalinux|fedora)
                OS_FLAVOR="rhel"
                APACHE_SVC="httpd"
                DNS_SVC="named"
                SSH_SVC="sshd"
                SAMBA_SVC="smb"
                echo -e "${GREEN}[+] Detected RHEL-based OS ($ID).${NC}"
                ;;
            *)
                echo -e "${YELLOW}[!] Unsupported OS: $ID. Defaulting to standard generic checks.${NC}"
                OS_FLAVOR="unknown"
                ;;
        esac
    else
        echo -e "${RED}[!] /etc/os-release not found. Cannot determine OS.${NC}"
    fi
}

# --- Helper Functions ---
ask_yn() {
    local prompt="$1"
    while true; do
        read -p "$(echo -e ${YELLOW}">> $prompt (y/n): "${NC})" yn
        case $yn in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Please answer yes (y) or no (n)." ;;
        esac
    done
}

print_header() {
    echo -e "\n============================================================"
    echo -e "${CYAN} AUTOMATED DIAGNOSTICS: $1 ${NC}"
    echo -e "============================================================"
}

print_resolve() {
    echo -e "\n${GREEN}[RECOMMENDATION] -> $1${NC}\n"
}

print_issue() {
    echo -e "${RED}[ISSUE FOUND] -> $1${NC}"
}

print_ok() {
    echo -e "${GREEN}[OK] -> $1${NC}"
}

check_service_status() {
    local svc="$1"
    echo -e "${CYAN}[*] Checking if $svc is running...${NC}"
    if systemctl is-active --quiet "$svc"; then
        print_ok "$svc is currently ACTIVE and RUNNING."
        return 0
    else
        local result=$(systemctl show "$svc" -p Result --value 2>/dev/null)
        local exit_code=$(systemctl show "$svc" -p ExecMainStatus --value 2>/dev/null)
        local restarts=$(systemctl show "$svc" -p NRestarts --value 2>/dev/null)
        print_issue "$svc is NOT running (Result: $result, Exit Code: $exit_code, Restarts: $restarts)"
        if [ -n "$restarts" ] && [ "$restarts" -gt 3 ] 2>/dev/null; then
            print_issue "$svc has restarted $restarts times — it may be crashlooping."
        fi
        return 1
    fi
}

check_port() {
    local port="$1"
    echo -e "${CYAN}[*] Checking if port $port is bound...${NC}"
    if ss -tulpn | grep -q ":$port "; then
        return 0
    else
        return 1
    fi
}

check_listen_address() {
    local port="$1"
    local svc_name="$2"
    echo -e "${CYAN}[*] Checking listen address for port $port...${NC}"
    local listen_line
    listen_line=$(ss -tulpn | grep ":$port ")
    if [ -z "$listen_line" ]; then
        print_issue "$svc_name is NOT listening on port $port at all."
        return 1
    fi
    # Check for wildcard/all-interfaces bindings first
    # 0.0.0.0:PORT = IPv4 wildcard, *:PORT = all, [::]:PORT or :::PORT = IPv6 wildcard
    if echo "$listen_line" | grep -qE "0\.0\.0\.0:$port|\*:$port|\[::\]:$port|:::$port"; then
        print_ok "$svc_name is listening on all interfaces on port $port."
        return 0
    fi
    # No wildcard found — check if it's localhost-only
    if echo "$listen_line" | grep -qE "127\.0\.0\.1:$port|\[::1\]:$port|::1:$port"; then
        print_issue "$svc_name is only listening on localhost (port $port). Scoring engines cannot reach it."
        return 1
    fi
    # Bound to a specific non-localhost address
    print_ok "$svc_name is listening on external interfaces on port $port."
    return 0
}

diagnose_from_logs() {
    local svc="$1"
    echo -e "\n${CYAN}[*] Fetching recent journal logs for $svc...${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    local logs
    logs=$(journalctl -u "$svc" -p err --no-pager -n 40 2>/dev/null)
    if [ -z "$logs" ]; then
        logs=$(journalctl -u "$svc" --no-pager -n 40 2>/dev/null)
    fi

    if [ -z "$logs" ]; then
        echo -e "${YELLOW}[!] No journal entries found for $svc.${NC}"
        return
    fi

    echo "$logs"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    echo -e "\n${CYAN}[*] Scanning logs for common failure patterns...${NC}"
    local found_pattern=0

    if echo "$logs" | grep -qi "address already in use"; then
        print_issue "Log indicates a port/address conflict — another process holds the port."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "permission denied"; then
        print_issue "Log indicates a permission denied error — check file ownership, SELinux, or capabilities."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "no such file\|file not found\|cannot open"; then
        print_issue "Log indicates a missing file — a config likely references a path that doesn't exist."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "syntax error\|unexpected end\|invalid command\|unknown directive"; then
        print_issue "Log indicates a configuration syntax error."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "segfault\|segmentation fault\|core dumped"; then
        print_issue "Log indicates the service crashed (segfault/core dump)."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "out of memory\|oom\|cannot allocate"; then
        print_issue "Log indicates an out-of-memory condition."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "ssl\|tls\|certificate"; then
        if echo "$logs" | grep -qi "error\|fail\|expired\|invalid"; then
            print_issue "Log indicates a TLS/certificate error — check cert paths and expiration."
            found_pattern=1
        fi
    fi
    if echo "$logs" | grep -qi "bind.*failed\|could not bind\|failed to listen"; then
        print_issue "Log indicates the service could not bind to its port."
        found_pattern=1
    fi
    if echo "$logs" | grep -qi "authentication fail\|login fail\|access denied\|password"; then
        print_issue "Log indicates authentication/access failures."
        found_pattern=1
    fi

    if [ "$found_pattern" -eq 0 ]; then
        echo -e "${YELLOW}[!] No common failure patterns matched. Review the log output above manually.${NC}"
    fi
}

# --- Service Modules ---

diag_apache() {
    print_header "Apache ($APACHE_SVC)"

    if ! check_service_status "$APACHE_SVC"; then
        echo -e "${CYAN}[*] Service is down. Running automated syntax validation...${NC}"
        if [[ "$OS_FLAVOR" == "rhel" ]]; then
            apachectl configtest >/dev/null 2>&1
        else
            apache2ctl configtest >/dev/null 2>&1
        fi

        if [ $? -ne 0 ]; then
            print_issue "Apache configuration syntax is broken."
            if [[ "$OS_FLAVOR" == "rhel" ]]; then
                echo -e "${CYAN}[*] Syntax error output:${NC}"
                apachectl configtest 2>&1
            else
                echo -e "${CYAN}[*] Syntax error output:${NC}"
                apache2ctl configtest 2>&1
            fi
            print_resolve "Fix the syntax error shown above and run 'systemctl start $APACHE_SVC'."
            return
        else
            print_ok "Apache syntax is perfectly fine."
            if check_port 80 || check_port 443; then
                print_issue "Another process is already using Port 80 or 443."
                echo -e "${CYAN}[*] Processes on port 80/443:${NC}"
                ss -tulpn | grep -E ":80 |:443 "
                print_resolve "Kill the conflicting process shown above, then start Apache."
                return
            fi
        fi
        diagnose_from_logs "$APACHE_SVC"
        return
    fi

    # Service is running — check if it's reachable for scoring
    check_listen_address 80 "Apache"

    if ask_yn "Is Apache running, but users are getting a 403 Forbidden error?"; then
        if [[ "$OS_FLAVOR" == "rhel" ]]; then
            echo -e "${CYAN}[*] Checking SELinux status...${NC}"
            if command -v getenforce >/dev/null && [[ "$(getenforce)" == "Enforcing" ]]; then
                print_issue "SELinux is Enforcing and likely blocking HTTPD read access."
                print_resolve "Apply the correct SELinux context: 'chcon -Rt httpd_sys_content_t /var/www/html'."
            fi
        fi
        print_resolve "Check standard Linux file permissions. The Apache user needs +r on files and +x on directories in the web root."
    fi
}

diag_nginx() {
    print_header "Nginx"

    if ! check_service_status "nginx"; then
        echo -e "${CYAN}[*] Nginx is down. Running syntax test...${NC}"
        nginx -t >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            print_issue "Nginx syntax test failed."
            echo -e "${CYAN}[*] Syntax error output:${NC}"
            nginx -t 2>&1
            print_resolve "Fix the syntax error shown above and run 'systemctl start nginx'."
            return
        else
            print_ok "Nginx syntax is valid."
            if check_port 80; then
                print_issue "Port 80 is currently occupied by another service."
                echo -e "${CYAN}[*] Processes on port 80:${NC}"
                ss -tulpn | grep ":80 "
                print_resolve "Kill the conflicting process shown above, then start Nginx."
                return
            fi
        fi
        diagnose_from_logs "nginx"
        return
    fi

    check_listen_address 80 "Nginx"

    if ask_yn "Are users experiencing 502 Bad Gateway errors?"; then
        print_resolve "Nginx is fine, but the upstream application (PHP-FPM, Node.js, Tomcat) is down or refusing connections. Verify the upstream service specified in your proxy_pass or fastcgi_pass directive is running."
    fi
}

diag_openssh() {
    print_header "OpenSSH ($SSH_SVC)"

    if ! check_service_status "$SSH_SVC"; then
        echo -e "${CYAN}[*] $SSH_SVC is down. Testing configuration syntax...${NC}"
        sshd -t >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            print_issue "There is a syntax error in /etc/ssh/sshd_config."
            echo -e "${CYAN}[*] Syntax error output:${NC}"
            sshd -t 2>&1
            print_resolve "Fix the syntax error shown above and run 'systemctl start $SSH_SVC'."
        else
            print_ok "sshd syntax is valid."
        fi
        diagnose_from_logs "$SSH_SVC"
        return
    fi

    check_listen_address 22 "OpenSSH"

    echo -e "${CYAN}[*] Checking if SSH allows Root Logins...${NC}"
    if grep -qE "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo -e "${YELLOW}[WARNING] PermitRootLogin is set to YES. This is a security risk.${NC}"
    else
        print_ok "Root login is restricted or properly configured via keys."
    fi

    if ask_yn "Are users getting 'Permission denied (publickey)'?"; then
        print_resolve "Ensure strict ownership/permissions. Home dir: 755 or 700. ~/.ssh dir: 700. ~/.ssh/authorized_keys: 600. Check /var/log/secure or /var/log/auth.log."
    fi
}

diag_postgres() {
    print_header "PostgreSQL"

    if ! check_service_status "postgresql"; then
        diagnose_from_logs "postgresql"
        return
    fi

    check_listen_address 5432 "PostgreSQL"

    if ask_yn "Are external users failing to connect or getting authentication errors?"; then
        print_resolve "Check pg_hba.conf. You likely need a rule like: 'host all all 0.0.0.0/0 scram-sha-256' to allow network authentication. Default is often 'peer' which only works for local Linux sockets."
    fi
}

diag_vsftpd() {
    print_header "vsftpd (FTP)"

    if ! check_service_status "vsftpd"; then
        echo -e "${CYAN}[*] vsftpd is down. Checking configuration...${NC}"
        # vsftpd has no built-in syntax test, so go straight to logs
        if [ -f /etc/vsftpd.conf ] || [ -f /etc/vsftpd/vsftpd.conf ]; then
            print_ok "vsftpd config file exists."
        else
            print_issue "vsftpd config file not found at /etc/vsftpd.conf or /etc/vsftpd/vsftpd.conf."
        fi
        diagnose_from_logs "vsftpd"
        return
    fi

    check_listen_address 21 "vsftpd"

    echo -e "${CYAN}[*] Checking key vsftpd settings...${NC}"
    local conf=""
    if [ -f /etc/vsftpd.conf ]; then
        conf="/etc/vsftpd.conf"
    elif [ -f /etc/vsftpd/vsftpd.conf ]; then
        conf="/etc/vsftpd/vsftpd.conf"
    fi
    if [ -n "$conf" ]; then
        if grep -qi "^anonymous_enable=YES" "$conf"; then
            echo -e "${YELLOW}[WARNING] Anonymous FTP access is enabled.${NC}"
        fi
        if grep -qi "^local_enable=NO" "$conf"; then
            print_issue "Local user login is disabled (local_enable=NO)."
            print_resolve "Set 'local_enable=YES' in $conf and restart vsftpd."
        fi
    fi
}

diag_samba() {
    print_header "Samba ($SAMBA_SVC)"

    if ! check_service_status "$SAMBA_SVC"; then
        echo -e "${CYAN}[*] $SAMBA_SVC is down. Checking config syntax...${NC}"
        if command -v testparm >/dev/null; then
            testparm -s /etc/samba/smb.conf >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                print_issue "Samba config syntax error."
                echo -e "${CYAN}[*] Syntax error output:${NC}"
                testparm -s /etc/samba/smb.conf 2>&1
                print_resolve "Fix the error shown above and restart $SAMBA_SVC."
            else
                print_ok "Samba config syntax is valid."
            fi
        fi
        diagnose_from_logs "$SAMBA_SVC"
        return
    fi

    check_listen_address 445 "Samba"

    if ask_yn "Can clients see shares but get 'Access Denied' when connecting?"; then
        print_resolve "Ensure the Samba user exists: 'smbpasswd -a <username>'. Also check share-level 'valid users' and filesystem permissions on the shared directory."
    fi
}

diag_dns() {
    print_header "BIND DNS ($DNS_SVC)"

    if ! check_service_status "$DNS_SVC"; then
        echo -e "${CYAN}[*] DNS service is down. Checking configuration...${NC}"
        if command -v named-checkconf >/dev/null; then
            named-checkconf >/dev/null 2>&1
            if [ $? -ne 0 ]; then
                print_issue "BIND configuration syntax error."
                echo -e "${CYAN}[*] Syntax error output:${NC}"
                named-checkconf 2>&1
                print_resolve "Fix the error shown above and restart $DNS_SVC."
            else
                print_ok "BIND named.conf syntax is valid."
            fi
        fi
        diagnose_from_logs "$DNS_SVC"
        return
    fi

    check_listen_address 53 "BIND DNS"

    if ask_yn "Is DNS running but queries are failing or returning SERVFAIL?"; then
        print_resolve "Check individual zone files with 'named-checkzone <domain> <zonefile>'. A single typo in a zone file (missing dot on FQDN, bad serial) will cause SERVFAIL for that zone."
    fi
}

# --- Main Menu ---
main() {
    while true; do
        echo ""
        echo "****************************************************************"
        echo -e "* ${CYAN}AUTOMATED INCIDENT RESPONSE EXPERT SYSTEM${NC}                    *"
        echo -e "* Detected Environment: ${GREEN}$OS_FLAVOR ($ID)${NC}"
        echo "****************************************************************"
        echo "Select a service to audit and diagnose:"
        echo "1) Apache2 / HTTPD"
        echo "2) Nginx"
        echo "3) OpenSSH"
        echo "4) PostgreSQL"
        echo "5) vsftpd (FTP)"
        echo "6) Samba (SMB)"
        echo "7) BIND DNS"
        echo "8) Exit"

        read -p ">> Select an option [1-8]: " choice

        case $choice in
            1) diag_apache ;;
            2) diag_nginx ;;
            3) diag_openssh ;;
            4) diag_postgres ;;
            5) diag_vsftpd ;;
            6) diag_samba ;;
            7) diag_dns ;;
            8) echo "Exiting."; exit 0 ;;
            *) echo "Invalid option." ;;
        esac
        echo -e "\n${GREEN}--- Diagnostics Complete ---${NC}"
    done
}

# --- Execution ---
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run this script as root (sudo). Many diagnostic commands require elevated privileges.${NC}"
  exit 1
fi

detect_os
main