#!/usr/bin/env bash
set -e

# PPHDEVUDP Manager with Remote API License Validation
# SECURE LOADER SCRIPT

# License API endpoint - Set this before running
LICENSE_API="https://pphdevapi.free.nf"

# Colors for output
tred() { tput setaf 1 2>/dev/null || echo ""; }
tgreen() { tput setaf 2 2>/dev/null || echo ""; }
tyellow() { tput setaf 3 2>/dev/null || echo ""; }
tblue() { tput setaf 4 2>/dev/null || echo ""; }
tcyan() { tput setaf 6 2>/dev/null || echo ""; }
tbold() { tput bold 2>/dev/null || echo ""; }
treset() { tput sgr0 2>/dev/null || echo ""; }

# Global variable for the secure URL
SECURE_DOWNLOAD_URL=""

# Utility functions
has_command() {
    local _command=$1
    type -P "$_command" > /dev/null 2>&1
}

curl() {
    command curl -L -f -q --retry 5 --retry-delay 10 --retry-max-time 60 "$@"
}

mktemp() {
    command mktemp "$@" "hyservinst.XXXXXXXXXX"
}

note() {
    local _msg="$1"
    echo -e "$(basename "$0"): $(tbold)note: $_msg$(treset)"
}

error() {
    local _msg="$1"
    echo -e "$(basename "$0"): $(tred)error: $_msg$(treset)"
}

install_software() {
    local package="$1"
    echo -e "${CYAN}Installing $package...${NC}"
    if has_command apt-get; then
        apt-get update -qq >/dev/null
        apt-get install -y "$package"
    elif has_command dnf; then
        dnf install -y "$package"
    elif has_command yum; then
        yum install -y "$package"
    else
        error "No supported package manager found. Please install $package manually."
        exit 1
    fi
}

check_environment() {
    echo -e "${BLUE}Checking environment and dependencies...${NC}"
    
    if [[ "x$(uname)" != "xLinux" ]]; then
        error "This script only supports Linux."
        exit 95
    fi
    
    case "$(uname -m)" in
        'i386' | 'i686') ARCHITECTURE='386' ;;
        'amd64' | 'x86_64') ARCHITECTURE='amd64' ;;
        'armv5tel' | 'armv6l' | 'armv7' | 'armv7l') ARCHITECTURE='arm' ;;
        'armv8' | 'aarch64') ARCHITECTURE='arm64' ;;
        'mips' | 'mipsle' | 'mips64' | 'mips64le') ARCHITECTURE='mipsle' ;;
        's390x') ARCHITECTURE='s390x' ;;
        *)
            error "The architecture '$(uname -a)' is not supported."
            exit 8
            ;;
    esac
    
    if [[ ! -d "/run/systemd/system" ]]; then
        error "This script only supports Linux distributions with systemd."
        exit 1
    fi

    # Install all dependencies needed for BOTH installer and manager
    local dependencies=("curl" "grep" "sqlite3" "jq" "redis-server" "procps")
    for dep in "${dependencies[@]}"; do
        if ! has_command "$dep"; then
            install_software "$dep"
        else
            echo -e "${GREEN}✓ $dep is already installed.${NC}"
        fi
    done
    
    # Ensure Redis is running
    if ! systemctl is-active redis-server >/dev/null 2>&1; then
        systemctl start redis-server
        systemctl enable redis-server
    fi
}

check_permission() {
    if [[ "$UID" -eq '0' ]]; then
        return
    fi
    error "Please run this script with root (sudo)."
    exit 13
}

# Validate license key via API
validate_license_key() {
    local key="$1"
    
    echo
    echo -e "$(tblue)═══════════════════════════════════════$(treset)"
    echo -e "$(tcyan)   Validating License Key...$(treset)"
    echo -e "$(tblue)═══════════════════════════════════════$(treset)"
    echo
    
    local encoded_key="UFBIREVWVURQLTIwMjYtQUU0MjVENjZCNjQ0RTRGQg=="
    local valid_key=$(echo "$encoded_key" | base64 -d 2>/dev/null)
    
    if [[ -z "$valid_key" ]]; then
        echo -e "$(tred)✗ System error: Cannot decode license key!$(treset)"
        return 1
    fi
    
    echo "Checking license key..."
    
    if [[ "$key" == "$valid_key" ]]; then
        echo -e "$(tgreen)✓ License key validated successfully!$(treset)"
        echo -e "$(tyellow)✓ Welcome to PPHDEVUDP Manager$(treset)"
        
        # Set download URL for Hysteria binary
        SECURE_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
        return 0
    else
        echo -e "$(tred)✗ Invalid license key!$(treset)"
        echo -e "$(tyellow)Please enter:$(treset)"
        return 1
    fi
}

# Prompt for license key
prompt_for_license() {
    while true; do
        echo
        echo -e "$(tbold)═══════════════════════════════════════$(treset)"
        echo -e "$(tcyan)   PPHDEVUDP Manager Installation$(treset)"
        echo -e "$(tbold)═══════════════════════════════════════$(treset)"
        echo
        echo -e "$(tyellow)Enter the license key to continue installation:$(treset)"
        echo -e "$(tyellow)Valid Key: $(treset)"
        echo
        echo -n "License key: "
        read -r LICENSE_KEY
        
        if [[ -z "$LICENSE_KEY" ]]; then
            echo -e "$(tred)✗ License key cannot be empty!$(treset)"
            sleep 1
            continue
        fi
        
        # Trim whitespace and convert to uppercase
        LICENSE_KEY=$(echo "$LICENSE_KEY" | xargs | tr '[:lower:]' '[:upper:]')
        
        if validate_license_key "$LICENSE_KEY"; then
            # Success, SECURE_DOWNLOAD_URL is now set
            break
        else
            # Failure, error messages were already printed
            echo
            echo -e "$(tyellow)Press Enter to try again, or Ctrl+C to cancel...$(treset)"
            read -n 1 -s
            clear
        fi
    done
}

# Prompt for Domain Name before installation
prompt_for_domain() {
    local default_domain
    default_domain=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    echo
    echo -n -e "${CYAN}Enter your IP or DNS for this server (default IP: $default_domain): ${NC}"
    read -r input_domain
    if [[ -z "$input_domain" ]]; then
        DOMAIN="$default_domain"
    else
        DOMAIN="$input_domain"
    fi
}

# Prompt for OBFS string before installation
prompt_for_obfs() {
    local default_obfs="pphdev"
    echo
    echo -n -e "${CYAN}Enter the OBFS string (default: $default_obfs): ${NC}"
    read -r input_obfs
    if [[ -z "$input_obfs" ]]; then
        OBFS="$default_obfs"
    else
        OBFS="$input_obfs"
    fi
}

# Values set by prompts
DOMAIN=""
OBFS=""
ARCHITECTURE=""

# Script paths
EXECUTABLE_INSTALL_PATH="/usr/local/bin/hysteria"
SYSTEMD_SERVICES_DIR="/etc/systemd/system"
CONFIG_DIR="/etc/hysteria"
USER_DB_LEGACY="$CONFIG_DIR/udpusers.db" # This is from old installer, we ignore it
CONFIG_FILE="$CONFIG_DIR/config.json"
REPO_URL="https://github.com/apernet/hysteria"

install_content() {
    local _install_flags="$1"
    local _content="$2"
    local _destination="$3"
    local _tmpfile
    _tmpfile=$(mktemp)
    echo -ne "Install $_destination ... "
    echo "$_content" > "$_tmpfile"
    if install "$_install_flags" "$_tmpfile" "$_destination"; then
        echo -e "ok"
    fi
    rm -f "$_tmpfile"
}

download_hysteria() {
    local _destination="$1"
    local _download_url="$REPO_URL/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
    echo "Downloading hysteria binary: $_download_url ..."
    if ! curl -R -H 'Cache-Control: no-cache' "$_download_url" -o "$_destination"; then
        error "Download failed! Please check your network and try again."
        return 11
    fi
    return 0
}

perform_install_hysteria_binary() {
    local _tmpfile
    _tmpfile=$(mktemp)
    if ! download_hysteria "$_tmpfile"; then
        rm -f "$_tmpfile"
        exit 11
    fi
    echo -ne "Installing hysteria executable ... "
    if install -Dm755 "$_tmpfile" "$EXECUTABLE_INSTALL_PATH"; then
        echo "ok"
    else
        exit 13
    fi
    rm -f "$_tmpfile"
}

tpl_hysteria_server_service_base() {
    local _config_name="$1"
    cat << EOF
[Unit]
Description=UDP Service
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/local/bin/hysteria"
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
}

tpl_hysteria_server_service() {
    tpl_hysteria_server_service_base 'config'
}

tpl_hysteria_server_x_service() {
    tpl_hysteria_server_service_base '%i'
}

tpl_etc_hysteria_config_json() {
    mkdir -p "$CONFIG_DIR"
    # We create an empty config first. The manager script will populate it.
    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": ":36712",
  "protocol": "udp",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 10,
  "down": "100 Mbps",
  "down_mbps": 20,
  "disable_udp": false,
  "insecure": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": []
  },
  "log": {
    "level": "info",
    "file": "/var/log/hysteria/hysteria.log"
  }
}
EOF
}

perform_install_hysteria_systemd() {
    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
    systemctl daemon-reload
}

# === NEW SECURE FUNCTION ===
perform_install_secure_manager() {
    local _manager_binary_path="/usr/local/bin/udp" # This is the final command
    
    echo
    echo -e "${BLUE}Downloading secure manager script...${NC}"
    echo -e "From: ${CYAN}$SECURE_DOWNLOAD_URL${NC}"
    
    # Download the compiled file
    if ! curl -o "$_manager_binary_path" "$SECURE_DOWNLOAD_URL"; then
        error "Failed to download secure manager binary."
        error "Please check your API's download_url and file hosting."
        return 1
    fi
    
    # Make it executable
    chmod +x "$_manager_binary_path"
    
    echo -e "${GREEN}✓ Manager script installed successfully.${NC}"
    echo -e "${GREEN}✓ You can now run the manager using the 'udp' command.${NC}"
}

setup_ssl() {
    echo "Installing SSL certificates..."
    openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
    openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" -out /etc/hysteria/hysteria.ca.crt
    openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" -out /etc/hysteria/hysteria.server.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") -days 3650 -in /etc/hysteria/hysteria.server.csr -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key -set_serial 01 -out /etc/hysteria/hysteria.server.crt
    echo "✓ SSL certificates installed successfully"
}

start_services() {
    echo "Starting UDP server..."
    apt-get update -qq >/dev/null
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
    sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
    apt-get install -y iptables-persistent
    
    local iface
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    local UDP_PORT=":36712"
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    ip6tables -t nat -A PREROUTING -i "$iface" -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
    
    sysctl net.ipv4.conf.all.rp_filter=0
    sysctl net.ipv4.conf."$iface".rp_filter=0
    
    echo "net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$iface.rp_filter=0" > /etc/sysctl.conf
    
    sysctl -p
    
    sudo iptables-save > /etc/iptables/rules.v4
    sudo ip6tables-save > /etc/iptables/rules.v6
    
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
    
    sleep 2
    if systemctl is-active hysteria-server.service >/dev/null 2>&1; then
        echo "✓ UDP server started successfully"
    else
        echo "⚠ Warning: UDP server may not have started correctly"
    fi
}

perform_install() {
    perform_install_hysteria_binary
    tpl_etc_hysteria_config_json
    perform_install_hysteria_systemd
    setup_ssl
    start_services
    
    # This is the new, secure part
    if ! perform_install_secure_manager; then
        error "Installation failed because the manager script could not be downloaded."
        exit 1
    fi

    echo
    echo -e "${GREEN}═══════════════════════════════════════════════════════$(treset)"
    echo -e "$(tbold)✓ Congratulations! PPHDEVUDP has been successfully installed!$(treset)"
    echo -e "${GREEN}═══════════════════════════════════════════════════════$(treset)"
    echo
    echo -e "$(tbold)Quick Start:$(treset)"
    echo -e "  Run: $(tblue)udp$(treset) to access the management menu"
    echo
    echo -e "$(tbold)Features:$(treset)"
    echo -e "  ✓ Multi-user with Expiry"
    echo -e "  ✓ Real-time Redis-based monitoring"
    echo -e "  ✓ Web-based status dashboard"
    echo
}

main() {
    check_permission
    check_environment
    prompt_for_license
    
    prompt_for_domain
    prompt_for_obfs
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/var/log/hysteria"
    
    perform_install
    
    # Self-destruct
    echo "Cleaning up installer..."
    rm -- "$0"
}

main "$@"
