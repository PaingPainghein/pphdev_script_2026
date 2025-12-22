#!/usr/bin/env bash
set -e

# UDP Manager with Remote API License Validation
# SECURE LOADER SCRIPT

# License API endpoint - Set this before running
LICENSE_API="http://pphdev/api"

# Colors for output
tred() { tput setaf 1 2>/dev/null || echo ""; }
tgreen() { tput setaf 2 2>/dev/null || echo ""; }
tyellow() { tput setaf 3 2>/dev/null || echo ""; }
tblue() { tput setaf 4 2>/dev/null || echo ""; }
tcyan() { tput setaf 6 2>/dev/null || echo ""; }
tbold() { tput bold 2>/dev/null || echo ""; }
treset() { tput sgr0 2>/dev/null || echo ""; }

# Color variables
RED=$(tred)
GREEN=$(tgreen)
YELLOW=$(tyellow)
BLUE=$(tblue)
CYAN=$(tcyan)
BOLD=$(tbold)
NC=$(treset) # No Color

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
    local server_ip=$(curl -4 -s --connect-timeout 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    local hostname=$(hostname)
    
    echo
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo -e "${CYAN}   Validating License Key...${NC}"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    echo
    
    local encoded_key="cHBoZGV2a2V5MjAyNg=="
    local hardcoded_key=$(echo "$encoded_key" | base64 -d 2>/dev/null || echo "")
    
    if [[ -z "$hardcoded_key" ]]; then
        echo -e "${RED}✗ System error: Cannot decode license key!${NC}"
        return 1
    fi
    
    # Check if it's the BASE64 encoded license key first
    echo "Checking license key format..."
    
    # First, try direct comparison
    if [[ "$key" == "$hardcoded_key" ]]; then
        echo -e "${GREEN}✓ License key validated successfully! (Direct Match)${NC}"
        
        # Set the download URL for Hysteria binary
        SECURE_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
        echo -e "${BLUE}✓ Download URL set: $SECURE_DOWNLOAD_URL${NC}"
        return 0
    fi
    
    # Second, check if user entered the BASE64 encoded version
    if [[ "$key" == "$encoded_key" ]]; then
        echo -e "${GREEN}✓ License key validated successfully!${NC}"
        echo -e "${YELLOW}✓ Decoded key: $hardcoded_key${NC}"
        
        # Set the download URL for Hysteria binary
        SECURE_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
        echo -e "${BLUE}✓ Download URL set: $SECURE_DOWNLOAD_URL${NC}"
        return 0
    fi
    
    # If not the hardcoded key, try API validation
    if [[ -z "$LICENSE_API" ]] || [[ "$LICENSE_API" == "http://pphdev/api" ]]; then
        echo -e "${YELLOW}⚠ LICENSE_API not configured or using default value!${NC}"
        echo -e "${YELLOW}Try using hardcoded key: $hardcoded_key${NC}"
        echo -e "${YELLOW}Or BASE64 encoded: $encoded_key${NC}"
        
        # Check if it's one of the demo keys
        if [[ "$key" == "ADMIN PaingPaingHein" ]] || [[ "$key" == "pphdev" ]]; then
            echo -e "${GREEN}✓ Demo key accepted! Using hardcoded key.${NC}"
            SECURE_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
            echo -e "${BLUE}✓ Download URL set: $SECURE_DOWNLOAD_URL${NC}"
            return 0
        fi
        
        return 1
    fi
    
    echo "Connecting to license server: $LICENSE_API ..."
    echo
    
    local response
    response=$(curl -s --connect-timeout 30 -X POST "$LICENSE_API/validate" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -d "{\"licenseKey\":\"$key\",\"hostname\":\"$hostname\",\"ipAddress\":\"$server_ip\"}" \
        2>&1)
    
    if [[ -z "$response" ]] || [[ "$response" =~ "curl:" ]] || [[ "$response" =~ "Could not resolve host" ]]; then
        echo -e "${RED}✗ Cannot verify the key! (Connection error)${NC}"
        echo -e "${YELLOW}Server: $LICENSE_API${NC}"
        echo -e "${YELLOW}Try using hardcoded key: $hardcoded_key${NC}"
        echo -e "${YELLOW}Or BASE64: $encoded_key${NC}"
        return 1
    fi
    
    # Use jq (which we installed) for safe parsing
    local valid=$(echo "$response" | jq -r '.valid // .success // false' 2>/dev/null)
    
    if [[ "$valid" == "true" ]] || [[ "$valid" == "1" ]]; then
        # === SECURE MODEL ===
        # Key မှန်ရင် download_url ကို ရှာမယ်
        local download_url=$(echo "$response" | jq -r '.download_url // .url // .file // empty' 2>/dev/null)
        
        if [[ -z "$download_url" ]]; then
            echo -e "${YELLOW}⚠ No custom download URL received from API, using default.${NC}"
            SECURE_DOWNLOAD_URL="https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-$ARCHITECTURE"
        else
            SECURE_DOWNLOAD_URL="$download_url"
        fi
        
        echo -e "${GREEN}✓ License key validated successfully! (API Check)${NC}"
        echo -e "${BLUE}✓ Download URL set: $SECURE_DOWNLOAD_URL${NC}"
        return 0 # Success
    else
        # Key မှားရင် Error ပြမယ်
        local error_msg=$(echo "$response" | jq -r '.error // .message // .reason // "Unknown error"' 2>/dev/null)
        local status=$(echo "$response" | jq -r '.status // .code // "NO_STATUS"' 2>/dev/null)
        
        echo -e "${RED}✗ License validation failed!${NC}"
        echo -e "${YELLOW}Server: $LICENSE_API${NC}"
        [[ "$status" != "NO_STATUS" ]] && echo -e "${YELLOW}Status: $status${NC}"
        [[ -n "$error_msg" ]] && echo -e "${YELLOW}Error: $error_msg${NC}"
        
        # Show raw response for debugging if error parsing failed
        if [[ -z "$error_msg" ]] || [[ "$error_msg" == "Unknown error" ]]; then
            echo -e "${YELLOW}Raw response: $response${NC}"
        fi
        
        echo -e "${YELLOW}Try using hardcoded key: $hardcoded_key${NC}"
        echo -e "${YELLOW}Or BASE64 encoded: $encoded_key${NC}"
        
        return 1 # Failure
    fi
}

# Prompt for license key
prompt_for_license() {
    while true; do
        echo
        echo -e "${BOLD}═══════════════════════════════════════${NC}"
        echo -e "${CYAN}   UDP Manager Installation${NC}"
        echo -e "${BOLD}═══════════════════════════════════════${NC}"
        echo
        echo -e "${YELLOW}A valid license key is required to install.${NC}"
        echo -e "${YELLOW}Hardcoded Key: pphdevkey2026 ${NC}"
        echo -e "${YELLOW}Or BASE64: cHBoZGV2a2V5MjAyNg==${NC}"
        echo -e "${YELLOW}Demo Key: ADMIN PaingPaingHein${NC}"
        echo -e "${YELLOW}Demo Key (t.me): pphdev${NC}"
        echo
        echo -n "Enter your license key: "
        read -r LICENSE_KEY
        
        if [[ -z "$LICENSE_KEY" ]]; then
            echo -e "${RED}✗ License key cannot be empty!${NC}"
            sleep 1
            continue
        fi
        
        # Trim whitespace
        LICENSE_KEY=$(echo "$LICENSE_KEY" | xargs)
        
        if validate_license_key "$LICENSE_KEY"; then
            # Success, SECURE_DOWNLOAD_URL is now set
            break
        else
            # Failure, error messages were already printed
            echo
            echo -e "${YELLOW}Press Enter to try again, or Ctrl+C to cancel...${NC}"
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
    echo -e "${GREEN}✓ Domain set to: $DOMAIN${NC}"
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
    echo -e "${GREEN}✓ OBFS set to: $OBFS${NC}"
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
    mkdir -p "/var/log/hysteria"
    
    # Get the actual IP if DOMAIN is empty
    if [[ -z "$DOMAIN" ]] || [[ "$DOMAIN" == "dynamic" ]]; then
        DOMAIN=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    fi
    
    cat << EOF > "$CONFIG_FILE"
{
  "server": "$DOMAIN",
  "listen": ":36712",
  "protocol": "udp",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 100,
  "down": "100 Mbps",
  "down_mbps": 100,
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
    echo -e "${GREEN}✓ Config file created at: $CONFIG_FILE${NC}"
}

perform_install_hysteria_systemd() {
    install_content -Dm644 "$(tpl_hysteria_server_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server.service"
    install_content -Dm644 "$(tpl_hysteria_server_x_service)" "$SYSTEMD_SERVICES_DIR/hysteria-server@.service"
    systemctl daemon-reload
}

# === FIXED VERSION: Secure manager installation ===
perform_install_secure_manager() {
    local _manager_binary_path="/usr/local/bin/udp" # This is the final command
    
    echo
    echo -e "${BLUE}Downloading secure manager script...${NC}"
    echo -e "From: ${CYAN}$SECURE_DOWNLOAD_URL${NC}"
    
    # Download the compiled file to a temporary location
    local _temp_path="/tmp/udp-binary-$$"
    if ! curl -o "$_temp_path" "$SECURE_DOWNLOAD_URL"; then
        error "Failed to download secure manager binary."
        error "Please check your API's download_url and file hosting."
        return 1
    fi
    
    # Make it executable
    chmod +x "$_temp_path"
    
    # Create the final udp script with working directory fix
    cat > "$_manager_binary_path" << 'EOF'
#!/bin/bash

# Fix: Always run from /etc/hysteria directory to find config.json
# Try multiple possible locations
if [ -d "/etc/hysteria" ]; then
    cd /etc/hysteria
elif [ -d "/root" ]; then
    cd /root
    # Try to copy config if it exists elsewhere
    if [ -f "/etc/hysteria/config.json" ] && [ ! -f "config.json" ]; then
        cp /etc/hysteria/config.json .
        echo "Copied config.json to current directory"
    fi
fi

# Get the actual binary path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UDP_BINARY="$SCRIPT_DIR/.udp-core"

# Check if binary exists
if [ ! -f "$UDP_BINARY" ]; then
    echo "Error: UDP binary not found at $UDP_BINARY"
    echo "Please reinstall the UDP manager."
    exit 1
fi

# Check if config.json exists
if [ ! -f "config.json" ]; then
    echo "Warning: config.json not found in current directory ($(pwd))"
    echo "Creating default config..."
    
    # Create minimal config
    cat > config.json << CONFIG_EOF
{
  "server": "$(curl -4 -s ifconfig.me 2>/dev/null || echo "127.0.0.1")",
  "listen": ":36712",
  "protocol": "udp",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up_mbps": 100,
  "down_mbps": 100,
  "obfs": "pphdev",
  "auth": {
    "mode": "passwords",
    "config": []
  }
}
CONFIG_EOF
    
    echo "Default config.json created"
fi

# Run the actual binary
exec "$UDP_BINARY" "$@"
EOF
    
    chmod +x "$_manager_binary_path"
    
    # Move the actual binary to a hidden location
    mv "$_temp_path" "/usr/local/bin/.udp-core"
    chmod +x "/usr/local/bin/.udp-core"
    
    echo -e "${GREEN}✓ Manager script installed successfully.${NC}"
    echo -e "${GREEN}✓ You can now run the manager using the 'udp' command.${NC}"
    echo -e "${YELLOW}✓ Working directory fix applied.${NC}"
}

setup_ssl() {
    echo "Installing SSL certificates..."
    
    # Create certificate directory
    mkdir -p "$CONFIG_DIR"
    
    # Get domain for certificate
    local cert_domain="$DOMAIN"
    if [[ -z "$cert_domain" ]]; then
        cert_domain=$(curl -4 -s --connect-timeout 3 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
    fi
    
    # Generate CA key
    if [ ! -f "/etc/hysteria/hysteria.ca.key" ]; then
        openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048
    fi
    
    # Generate CA certificate
    if [ ! -f "/etc/hysteria/hysteria.ca.crt" ]; then
        openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key \
            -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" \
            -out /etc/hysteria/hysteria.ca.crt
    fi
    
    # Generate server key
    if [ ! -f "/etc/hysteria/hysteria.server.key" ]; then
        openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key \
            -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$cert_domain" \
            -out /etc/hysteria/hysteria.server.csr
    fi
    
    # Generate server certificate
    if [ ! -f "/etc/hysteria/hysteria.server.crt" ]; then
        openssl x509 -req -extfile <(printf "subjectAltName=DNS:$cert_domain,DNS:$cert_domain") \
            -days 3650 -in /etc/hysteria/hysteria.server.csr \
            -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key \
            -set_serial 01 -out /etc/hysteria/hysteria.server.crt
    fi
    
    echo "✓ SSL certificates installed successfully"
}

start_services() {
    echo "Starting UDP server..."
    apt-get update -qq >/dev/null
    
    # Install iptables-persistent if not installed
    if ! has_command iptables-persistent; then
        sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
        sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
        apt-get install -y iptables-persistent
    fi
    
    # Get network interface
    local iface
    iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    local UDP_PORT=":36712"
    
    # Set up iptables rules
    iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -i "$iface" -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT 2>/dev/null || true
    
    # Configure sysctl
    sysctl net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
    sysctl net.ipv4.conf."$iface".rp_filter=0 2>/dev/null || true
    
    # Update sysctl.conf
    cat > /etc/sysctl.conf << SYSCTL_EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$iface.rp_filter=0
SYSCTL_EOF
    
    sysctl -p 2>/dev/null || true
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    
    # Start hysteria service
    systemctl enable hysteria-server.service
    systemctl start hysteria-server.service
    
    sleep 2
    if systemctl is-active hysteria-server.service >/dev/null 2>&1; then
        echo "✓ UDP server started successfully"
    else
        echo "⚠ Warning: UDP server may not have started correctly"
        echo "Check status with: systemctl status hysteria-server.service"
    fi
}

perform_install() {
    echo -e "${BLUE}Starting installation process...${NC}"
    
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
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}✓ Congratulations! UDP has been successfully installed!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${BOLD}Quick Start:${NC}"
    echo -e "  Run: ${BLUE}udp${NC} to access the management menu"
    echo
    echo -e "${BOLD}Features:${NC}"
    echo -e "  ✓ Multi-user with Expiry"
    echo -e "  ✓ Real-time Redis-based monitoring"
    echo -e "  ✓ Web-based status dashboard"
    echo
    echo -e "${YELLOW}Note: The 'udp' command will automatically handle config.json${NC}"
    echo -e "${YELLOW}even if it's not found in the current directory.${NC}"
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
    sleep 2
    echo -e "${GREEN}✓ Installation complete!${NC}"
}

main "$@"
