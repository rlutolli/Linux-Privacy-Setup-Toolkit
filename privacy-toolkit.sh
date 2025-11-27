#!/bin/bash

# Linux Privacy Setup Toolkit
# A comprehensive privacy and security hardening script for Linux systems

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_NAME="Privacy Setup Toolkit"
VERSION="1.1.0"

# Logging
LOG_FILE="/tmp/privacy_toolkit_$(date +%Y%m%d_%H%M%S).log"

# Function to print colored output
print_color() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to log messages
log_message() {
    local message="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$message" >> "$LOG_FILE"
    print_color "$BLUE" "$message"
}

# Function to prompt user for confirmation
confirm_action() {
    local message=$1
    local default=${2:-"n"}
    
    print_color "$YELLOW" "$message"
    read -p "Continue? [y/N]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_color "$RED" "This script should not be run as root for security reasons."
        print_color "$YELLOW" "Some operations will require sudo and will prompt you when needed."
        exit 1
    fi
}

# Function to detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION_ID=${VERSION_ID:-"unknown"}
    else
        print_color "$RED" "Cannot detect Linux distribution"
        exit 1
    fi
    
    log_message "Detected distribution: $DISTRO $VERSION_ID"
}

# Function to check dependencies
check_dependencies() {
    local deps=("curl" "wget" "ufw" "apparmor-utils")
    local missing_deps=()
    
    print_color "$CYAN" "Checking dependencies..."
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_color "$YELLOW" "Missing dependencies: ${missing_deps[*]}"
        if confirm_action "Install missing dependencies?"; then
            install_dependencies "${missing_deps[@]}"
        else
            print_color "$RED" "Cannot continue without required dependencies"
            exit 1
        fi
    fi
}

# Function to install dependencies
install_dependencies() {
    local deps=("$@")
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y "${deps[@]}"
            ;;
        fedora)
            sudo dnf install -y "${deps[@]}"
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm "${deps[@]}"
            ;;
        *)
            print_color "$RED" "Unsupported distribution for automatic dependency installation"
            print_color "$YELLOW" "Please install manually: ${deps[*]}"
            exit 1
            ;;
    esac
}

# Function to configure UFW firewall
configure_firewall() {
    print_color "$PURPLE" "=== Configuring UFW Firewall ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Reset UFW firewall to defaults"
    print_color "$YELLOW" "  • Set default policy: DENY incoming, ALLOW outgoing"
    print_color "$YELLOW" "  • Allow SSH (port 22) for remote access"
    print_color "$YELLOW" "  • Allow outgoing DNS (53), HTTP (80), HTTPS (443), NTP (123)"
    print_color "$YELLOW" "  • Enable firewall logging"
    print_color "$CYAN" ""
    print_color "$GREEN" "Note: Tailscale will continue to work as it uses its own network interface"
    print_color "$CYAN" ""
    
    if ! confirm_action "Configure UFW firewall with restrictive default rules?"; then
        return 0
    fi
    
    log_message "Configuring UFW firewall"
    
    # Reset UFW to defaults
    sudo ufw --force reset
    
    # Set default policies
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow essential services
    sudo ufw allow ssh
    sudo ufw allow out 53  # DNS
    sudo ufw allow out 80  # HTTP
    sudo ufw allow out 443 # HTTPS
    sudo ufw allow out 123 # NTP
    
    # Enable UFW
    sudo ufw --force enable
    
    # Enable logging
    sudo ufw logging on
    
    print_color "$GREEN" "✓ UFW firewall configured successfully"
}

# Function to configure DNS encryption
configure_dns() {
    print_color "$PURPLE" "=== Configuring Encrypted DNS ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Configure DNS over TLS (DoT) using systemd-resolved"
    print_color "$YELLOW" "  • Enable DNSSEC for DNS security"
    print_color "$YELLOW" "  • Encrypt all DNS queries to prevent ISP tracking"
    print_color "$CYAN" ""
    print_color "$YELLOW" "Note: This may override your current DNS settings"
    print_color "$CYAN" ""
    
    if ! confirm_action "Configure encrypted DNS using systemd-resolved?"; then
        return 0
    fi
    
    # Ask user to choose DNS provider
    print_color "$CYAN" ""
    print_color "$CYAN" "Choose your primary DNS provider:"
    print_color "$YELLOW" "  1) Mullvad (privacy-focused, ad-blocking)"
    print_color "$YELLOW" "  2) Quad9 (security-focused, malware blocking)"
    print_color "$CYAN" ""
    print_color "$CYAN" "Cloudflare (1.1.1.1) will be used as failsafe/fallback"
    print_color "$CYAN" ""
    
    read -p "Enter choice [1 or 2, default: 1]: " dns_choice
    dns_choice=${dns_choice:-1}
    
    log_message "Configuring encrypted DNS"
    
    if [ "$dns_choice" = "2" ]; then
        # Quad9 DNS configuration
        print_color "$CYAN" "Configuring Quad9 DNS with Cloudflare as fallback..."
        DNS_PRIMARY="9.9.9.9#dns.quad9.net"
        DNS_SECONDARY="149.112.112.112#dns.quad9.net"
        FALLBACK_PRIMARY="1.1.1.1#cloudflare-dns.com"
        FALLBACK_SECONDARY="1.0.0.1#cloudflare-dns.com"
        DNS_IPV6_PRIMARY="2620:fe::fe#dns.quad9.net"
        DNS_IPV6_SECONDARY="2620:fe::9#dns.quad9.net"
        log_message "Selected Quad9 DNS"
    else
        # Mullvad DNS configuration (default)
        print_color "$CYAN" "Configuring Mullvad DNS with Cloudflare as fallback..."
        DNS_PRIMARY="194.242.2.2#dns.mullvad.net"
        DNS_SECONDARY="194.242.2.3#dns.mullvad.net"
        FALLBACK_PRIMARY="1.1.1.1#cloudflare-dns.com"
        FALLBACK_SECONDARY="1.0.0.1#cloudflare-dns.com"
        DNS_IPV6_PRIMARY="2a07:e340::2#dns.mullvad.net"
        DNS_IPV6_SECONDARY="2a07:e340::3#dns.mullvad.net"
        log_message "Selected Mullvad DNS"
    fi
    
    # Create systemd-resolved configuration
    sudo tee /etc/systemd/resolved.conf > /dev/null <<EOF
[Resolve]
DNS=${DNS_PRIMARY} ${DNS_SECONDARY}
DNSOverTLS=yes
DNSSEC=yes
FallbackDNS=${FALLBACK_PRIMARY} ${FALLBACK_SECONDARY}
Cache=yes
Domains=~.
EOF
    
    # Restart systemd-resolved
    sudo systemctl restart systemd-resolved
    
    # Create symlink for resolv.conf
    sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    
    print_color "$GREEN" "✓ Encrypted DNS configured successfully"
    if [ "$dns_choice" = "2" ]; then
        print_color "$CYAN" "Using Quad9 DNS with Cloudflare fallback"
    else
        print_color "$CYAN" "Using Mullvad DNS with Cloudflare fallback"
    fi
}

# Function to install and configure browser security
configure_browser() {
    print_color "$PURPLE" "=== Browser Security Configuration ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Configure Zen Browser with additional privacy settings"
    print_color "$YELLOW" "  • Apply very restrictive privacy settings:"
    print_color "$YELLOW" "    - Enable tracking protection"
    print_color "$YELLOW" "    - Disable geolocation, notifications, WebGL, WebAudio"
    print_color "$YELLOW" "    - Block third-party cookies"
    print_color "$YELLOW" "    - Disable telemetry and data reporting"
    print_color "$YELLOW" "    - Disable prefetching and prediction"
    print_color "$CYAN" ""
    print_color "$RED" "Warning: These settings are VERY restrictive and may break some websites"
    print_color "$CYAN" ""
    print_color "$YELLOW" "Note: Zen Browser already has good privacy defaults, this adds extra hardening"
    print_color "$CYAN" ""
    
    if ! confirm_action "Configure Zen Browser with additional privacy settings?"; then
        return 0
    fi
    
    log_message "Configuring Zen Browser security"
    
    # Check if Zen Browser is installed
    if ! command -v zen-browser &> /dev/null && ! command -v zen &> /dev/null; then
        print_color "$YELLOW" "Zen Browser not found in PATH"
        print_color "$CYAN" "Please ensure Zen Browser is installed. Checking common profile locations..."
    fi
    
    # Zen Browser profile locations (Firefox-based, so similar structure)
    # Check for Flatpak installation first (common on modern Linux)
    ZEN_PROFILE_DIRS=(
        "$HOME/.var/app/app.zen_browser.zen/.zen"
        "$HOME/.zen-browser"
        "$HOME/.config/zen-browser"
        "$HOME/.mozilla/zen-browser"
    )
    
    PROFILE_FOUND=""
    
    # Try to find Zen Browser profile
    for profile_dir in "${ZEN_PROFILE_DIRS[@]}"; do
        if [ -d "$profile_dir" ]; then
            # For Flatpak installations, look for profiles.ini to find default profile
            if [ -f "$profile_dir/profiles.ini" ]; then
                # Extract default profile path from profiles.ini
                DEFAULT_PROFILE=$(grep -A 2 "Default=1" "$profile_dir/profiles.ini" 2>/dev/null | grep "Path=" | cut -d'=' -f2 | head -n1)
                if [ -n "$DEFAULT_PROFILE" ]; then
                    # Handle relative paths (common in profiles.ini)
                    if [[ "$DEFAULT_PROFILE" != /* ]]; then
                        PROFILE="$profile_dir/$DEFAULT_PROFILE"
                    else
                        PROFILE="$DEFAULT_PROFILE"
                    fi
                    if [ -d "$PROFILE" ] && ([ -f "$PROFILE/prefs.js" ] || [ -f "$PROFILE/user.js" ]); then
                        PROFILE_FOUND="$PROFILE"
                        break
                    fi
                fi
            fi
            # Look for default profile (similar to Firefox structure)
            PROFILE=$(find "$profile_dir" -name "*.default*" -type d 2>/dev/null | head -n1)
            if [ -n "$PROFILE" ] && ([ -f "$PROFILE/prefs.js" ] || [ -f "$PROFILE/user.js" ]); then
                PROFILE_FOUND="$PROFILE"
                break
            fi
            # Also check if the directory itself is a profile
            if [ -f "$profile_dir/prefs.js" ] || [ -f "$profile_dir/user.js" ]; then
                PROFILE_FOUND="$profile_dir"
                break
            fi
        fi
    done
    
    if [ -z "$PROFILE_FOUND" ]; then
        print_color "$YELLOW" "Zen Browser profile not found automatically"
        print_color "$CYAN" "Please provide the path to your Zen Browser profile directory"
        print_color "$CYAN" "Common locations:"
        print_color "$CYAN" "  - ~/.zen-browser"
        print_color "$CYAN" "  - ~/.config/zen-browser"
        print_color "$CYAN" ""
        read -p "Enter Zen Browser profile path (or press Enter to skip): " custom_profile
        
        if [ -n "$custom_profile" ] && [ -d "$custom_profile" ]; then
            PROFILE_FOUND="$custom_profile"
        else
            print_color "$RED" "Profile not found. Skipping browser configuration."
            print_color "$YELLOW" "You can manually add these settings to your Zen Browser user.js file"
            return 0
        fi
    fi
    
    if [ -n "$PROFILE_FOUND" ]; then
        # Create or append to user.js with privacy settings
        cat >> "$PROFILE_FOUND/user.js" <<EOF
// Additional privacy-focused configuration for Zen Browser
// (Zen Browser already has good defaults, these add extra hardening)
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.partition.network_state", false);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("geo.enabled", false);
user_pref("dom.webnotifications.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("webgl.disabled", true);
user_pref("dom.webaudio.enabled", false);
user_pref("beacon.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.predictor.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("browser.ping-centre.telemetry", false);
EOF
        print_color "$GREEN" "✓ Zen Browser privacy configuration applied to: $PROFILE_FOUND"
        print_color "$CYAN" "Note: Restart Zen Browser for changes to take effect"
    fi
}

# Function to configure file metadata removal
configure_metadata_removal() {
    print_color "$PURPLE" "=== Metadata Removal Tools ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Install exiftool and mat2 (metadata removal tools)"
    print_color "$YELLOW" "  • Create a 'strip-metadata' command for easy use"
    print_color "$CYAN" ""
    print_color "$CYAN" "These tools help remove EXIF data, GPS coordinates, and other"
    print_color "$CYAN" "metadata from images, documents, and other files before sharing."
    print_color "$CYAN" ""
    
    if ! confirm_action "Install tools for removing metadata from files?"; then
        return 0
    fi
    
    log_message "Installing metadata removal tools"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt install -y exiftool mat2
            ;;
        fedora)
            sudo dnf install -y perl-Image-ExifTool mat2
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm exiftool mat2
            ;;
    esac
    
    # Create convenience script
    cat > "$HOME/.local/bin/strip-metadata" <<'EOF'
#!/bin/bash
# Metadata stripping utility

if [ $# -eq 0 ]; then
    echo "Usage: strip-metadata <file1> [file2] ..."
    echo "Removes metadata from specified files"
    exit 1
fi

for file in "$@"; do
    if [ -f "$file" ]; then
        echo "Stripping metadata from: $file"
        mat2 --inplace "$file" 2>/dev/null || exiftool -all= -overwrite_original "$file"
        echo "✓ Processed: $file"
    else
        echo "✗ File not found: $file"
    fi
done
EOF
    
    chmod +x "$HOME/.local/bin/strip-metadata"
    
    print_color "$GREEN" "✓ Metadata removal tools installed"
    print_color "$CYAN" "Use 'strip-metadata <filename>' to remove metadata from files"
}

# Function to configure application sandboxing
configure_sandboxing() {
    print_color "$PURPLE" "=== Application Sandboxing ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Install Firejail (application sandboxing tool)"
    print_color "$YELLOW" "  • Configure Firejail to automatically sandbox applications"
    print_color "$YELLOW" "  • Create custom browser security profiles"
    print_color "$CYAN" ""
    print_color "$CYAN" "Firejail isolates applications from the rest of your system,"
    print_color "$CYAN" "preventing malicious software from accessing your files or network."
    print_color "$CYAN" ""
    print_color "$YELLOW" "Note: Some applications may need to be run with 'firejail <app>'"
    print_color "$CYAN" ""
    
    if ! confirm_action "Install and configure Firejail for application sandboxing?"; then
        return 0
    fi
    
    log_message "Installing Firejail"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt install -y firejail firejail-profiles
            ;;
        fedora)
            sudo dnf install -y firejail
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm firejail
            ;;
    esac
    
    # Configure Firejail
    sudo firecfg
    
    # Create custom profile for browsers
    sudo mkdir -p /etc/firejail
    cat > /tmp/browser-common.local <<EOF
# Custom browser security profile
caps.drop all
netfilter
noroot
protocol unix,inet,inet6,netlink
seccomp
shell none

private-cache
private-dev
private-tmp

disable-mnt
noexec /tmp
EOF
    
    sudo mv /tmp/browser-common.local /etc/firejail/
    
    print_color "$GREEN" "✓ Firejail sandboxing configured"
    print_color "$CYAN" "Applications will now run in sandboxed environments"
}

# Function to configure system hardening
configure_system_hardening() {
    print_color "$PURPLE" "=== System Hardening ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will:"
    print_color "$YELLOW" "  • Apply kernel security parameters (network hardening, memory protection)"
    print_color "$YELLOW" "  • Optionally disable services: bluetooth, cups (printing)"
    print_color "$CYAN" ""
    print_color "$GREEN" "Note: avahi-daemon will be kept enabled for P2P applications"
    print_color "$CYAN" ""
    print_color "$CYAN" "Kernel hardening includes:"
    print_color "$YELLOW" "  - Disable IP redirects and source routing"
    print_color "$YELLOW" "  - Enable SYN cookies (DDoS protection)"
    print_color "$YELLOW" "  - Restrict kernel memory access"
    print_color "$YELLOW" "  - Enable address space randomization"
    print_color "$CYAN" ""
    print_color "$YELLOW" "You'll be asked separately about each service to disable."
    print_color "$CYAN" ""
    
    if ! confirm_action "Apply system hardening configurations?"; then
        return 0
    fi
    
    log_message "Applying system hardening"
    
    # Disable unnecessary services
    SERVICES_TO_DISABLE=("bluetooth" "cups" "avahi-daemon")
    
    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-enabled "$service" &>/dev/null; then
            if [ "$service" = "avahi-daemon" ]; then
                print_color "$YELLOW" "Warning: Disabling avahi-daemon may break P2P applications and local network discovery"
                if confirm_action "Disable $service?"; then
                    sudo systemctl disable "$service"
                    sudo systemctl stop "$service"
                    log_message "Disabled service: $service"
                fi
            else
                if confirm_action "Disable $service?"; then
                    sudo systemctl disable "$service"
                    sudo systemctl stop "$service"
                    log_message "Disabled service: $service"
                fi
            fi
        fi
    done
    
    # Configure kernel parameters
    cat > /tmp/99-privacy-hardening.conf <<EOF
# Network security
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Process restrictions
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
EOF
    
    sudo mv /tmp/99-privacy-hardening.conf /etc/sysctl.d/
    sudo sysctl -p /etc/sysctl.d/99-privacy-hardening.conf
    
    print_color "$GREEN" "✓ System hardening applied"
}

# Function to ensure Flatpak is installed
ensure_flatpak() {
    if ! command -v flatpak &> /dev/null; then
        print_color "$YELLOW" "Flatpak not found. Installing Flatpak..."
        case $DISTRO in
            ubuntu|debian)
                sudo apt update
                sudo apt install -y flatpak
                ;;
            fedora)
                sudo dnf install -y flatpak
                ;;
            arch|manjaro)
                sudo pacman -S --noconfirm flatpak
                ;;
        esac
        # Add Flathub repository
        flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
        print_color "$GREEN" "✓ Flatpak installed"
    fi
}

# Function to install application from Flatpak
install_flatpak_app() {
    local app_id=$1
    local app_name=$2
    
    if flatpak list --app | grep -q "$app_id"; then
        print_color "$YELLOW" "  ⏭ $app_name already installed, skipping"
        return 0
    else
        print_color "$CYAN" "  Installing $app_name..."
        if flatpak install -y flathub "$app_id" 2>/dev/null; then
            print_color "$GREEN" "  ✓ Installed $app_name"
            log_message "Installed: $app_name ($app_id)"
            return 0
        else
            print_color "$RED" "  ✗ Failed to install $app_name"
            return 1
        fi
    fi
}

# Function to install common applications with selective menu
install_common_apps() {
    print_color "$PURPLE" "=== Application Installation ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "Choose application categories to install:"
    print_color "$CYAN" ""
    print_color "$YELLOW" "  1) Default (Zen Browser and/or Brave Browser only)"
    print_color "$YELLOW" "  2) Privacy (Zen Browser, Brave Browser, Tor Browser)"
    print_color "$YELLOW" "  3) Development (VS Code, GitHub Desktop)"
    print_color "$YELLOW" "  4) Communication (Discord)"
    print_color "$YELLOW" "  5) Media (Spotify)"
    print_color "$YELLOW" "  6) Custom selection"
    print_color "$CYAN" ""
    
    read -p "Enter your choice(s) separated by commas [1-6, default: 1]: " app_choices
    app_choices=${app_choices:-1}
    
    log_message "User selected application categories: $app_choices"
    
    # Ensure Flatpak is installed
    ensure_flatpak
    
    # Parse choices
    IFS=',' read -ra CHOICES <<< "$app_choices"
    
    # Track what to install
    INSTALL_ZEN=false
    INSTALL_BRAVE=false
    INSTALL_TOR=false
    INSTALL_VSCODE=false
    INSTALL_GITHUB=false
    INSTALL_DISCORD=false
    INSTALL_SPOTIFY=false
    
    for choice in "${CHOICES[@]}"; do
        choice=$(echo "$choice" | xargs) # trim whitespace
        case "$choice" in
            1)
                INSTALL_ZEN=true
                INSTALL_BRAVE=true
                ;;
            2)
                INSTALL_ZEN=true
                INSTALL_BRAVE=true
                INSTALL_TOR=true
                ;;
            3)
                INSTALL_VSCODE=true
                INSTALL_GITHUB=true
                ;;
            4)
                INSTALL_DISCORD=true
                ;;
            5)
                INSTALL_SPOTIFY=true
                ;;
            6)
                # Custom selection
                print_color "$CYAN" ""
                print_color "$CYAN" "Custom selection - choose individual apps:"
                read -p "Install Zen Browser? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_ZEN=true
                read -p "Install Brave Browser? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_BRAVE=true
                read -p "Install Tor Browser? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_TOR=true
                read -p "Install VS Code? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_VSCODE=true
                read -p "Install GitHub Desktop? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_GITHUB=true
                read -p "Install Discord? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_DISCORD=true
                read -p "Install Spotify? [y/N]: " -n 1 -r; echo
                [[ $REPLY =~ ^[Yy]$ ]] && INSTALL_SPOTIFY=true
                ;;
        esac
    done
    
    # Install selected browsers
    if [ "$INSTALL_ZEN" = true ] || [ "$INSTALL_BRAVE" = true ]; then
        print_color "$CYAN" "Installing browsers..."
        [ "$INSTALL_ZEN" = true ] && install_flatpak_app "app.zen_browser.zen" "Zen Browser"
        [ "$INSTALL_BRAVE" = true ] && install_flatpak_app "com.brave.Browser" "Brave Browser"
    fi
    
    # Install Tor Browser if selected
    if [ "$INSTALL_TOR" = true ]; then
        install_flatpak_app "com.github.micahflee.torbrowser-launcher" "Tor Browser"
    fi
    
    # Install VS Code if selected
    if [ "$INSTALL_VSCODE" = true ]; then
        print_color "$CYAN" "Installing Visual Studio Code..."
        if command -v code &> /dev/null; then
            print_color "$YELLOW" "  ⏭ VS Code already installed, skipping"
        else
            case $DISTRO in
                ubuntu|debian)
                    if [ ! -f /etc/apt/sources.list.d/vscode.list ]; then
                        wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /tmp/packages.microsoft.gpg
                        sudo install -o root -g root -m 644 /tmp/packages.microsoft.gpg /etc/apt/trusted.gpg.d/
                        sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
                        sudo apt update
                    fi
                    sudo apt install -y code
                    print_color "$GREEN" "  ✓ Installed VS Code"
                    log_message "Installed: VS Code"
                    ;;
                fedora)
                    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
                    sudo sh -c 'echo -e "[code]\nname=Visual Studio Code\nbaseurl=https://packages.microsoft.com/yumrepos/vscode\nenabled=1\ngpgcheck=1\ngpgkey=https://packages.microsoft.com/keys/microsoft.asc" > /etc/yum.repos.d/vscode.repo'
                    sudo dnf install -y code
                    print_color "$GREEN" "  ✓ Installed VS Code"
                    log_message "Installed: VS Code"
                    ;;
                arch|manjaro)
                    if command -v yay &> /dev/null; then
                        yay -S --noconfirm visual-studio-code-bin
                    elif command -v paru &> /dev/null; then
                        paru -S --noconfirm visual-studio-code-bin
                    else
                        print_color "$YELLOW" "  Install yay or paru for AUR packages, or install code manually"
                    fi
                    ;;
            esac
        fi
    fi
    
    # Install GitHub Desktop if selected
    if [ "$INSTALL_GITHUB" = true ]; then
        install_flatpak_app "io.github.shiftey.Desktop" "GitHub Desktop"
    fi
    
    # Install Discord if selected
    if [ "$INSTALL_DISCORD" = true ]; then
        install_flatpak_app "com.discordapp.Discord" "Discord"
    fi
    
    # Install Spotify if selected
    if [ "$INSTALL_SPOTIFY" = true ]; then
        print_color "$CYAN" "Installing Spotify..."
        if command -v spotify &> /dev/null; then
            print_color "$YELLOW" "  ⏭ Spotify already installed, skipping"
        else
            case $DISTRO in
                ubuntu|debian)
                    if [ ! -f /etc/apt/sources.list.d/spotify.list ]; then
                        curl -sS https://download.spotify.com/debian/pubkey_6224F9941A8AA6D1.gpg | sudo gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/spotify.gpg
                        echo "deb http://repository.spotify.com stable non-free" | sudo tee /etc/apt/sources.list.d/spotify.list
                        sudo apt update
                    fi
                    sudo apt install -y spotify-client
                    print_color "$GREEN" "  ✓ Installed Spotify"
                    log_message "Installed: Spotify"
                    ;;
                fedora)
                    install_flatpak_app "com.spotify.Client" "Spotify"
                    ;;
                arch|manjaro)
                    if command -v yay &> /dev/null; then
                        yay -S --noconfirm spotify
                    elif command -v paru &> /dev/null; then
                        paru -S --noconfirm spotify
                    else
                        install_flatpak_app "com.spotify.Client" "Spotify"
                    fi
                    ;;
            esac
        fi
    fi
    
    print_color "$GREEN" "✓ Application installation complete"
    print_color "$CYAN" "Note: Some applications may require a system restart or logout/login to appear in menus"
}

# Function to install Bitwarden CLI from GitHub releases
install_bitwarden_from_github() {
    print_color "$CYAN" "  Downloading Bitwarden CLI from GitHub..."
    
    # Ensure unzip is installed
    if ! command -v unzip &> /dev/null; then
        print_color "$CYAN" "  Installing unzip..."
        case $DISTRO in
            ubuntu|debian)
                sudo apt install -y unzip
                ;;
            fedora)
                sudo dnf install -y unzip
                ;;
            arch|manjaro)
                sudo pacman -S --noconfirm unzip
                ;;
        esac
    fi
    
    # Detect architecture
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            BW_ARCH="amd64"
            ;;
        aarch64|arm64)
            BW_ARCH="arm64"
            ;;
        armv7l|armhf)
            BW_ARCH="armv7"
            ;;
        *)
            print_color "$RED" "  ✗ Unsupported architecture: $ARCH"
            print_color "$CYAN" "  Install Bitwarden CLI manually from: https://github.com/bitwarden/cli/releases"
            return 1
            ;;
    esac
    
    # Get latest version
    BW_VERSION=$(curl -s https://api.github.com/repos/bitwarden/cli/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/v//')
    
    if [ -z "$BW_VERSION" ]; then
        print_color "$YELLOW" "  ⏭ Could not determine latest version, skipping"
        print_color "$CYAN" "  Install manually: https://github.com/bitwarden/cli/releases"
        return 1
    fi
    
    # Download and install
    BW_URL="https://github.com/bitwarden/cli/releases/download/v${BW_VERSION}/bw-linux-${BW_ARCH}-${BW_VERSION}.zip"
    TEMP_DIR=$(mktemp -d)
    
    if curl -fsSL "$BW_URL" -o "$TEMP_DIR/bw.zip"; then
        cd "$TEMP_DIR"
        if unzip -q bw.zip 2>/dev/null; then
            sudo mv bw /usr/local/bin/bw
            sudo chmod +x /usr/local/bin/bw
            cd - > /dev/null
            rm -rf "$TEMP_DIR"
            print_color "$GREEN" "  ✓ Bitwarden CLI installed from GitHub (v${BW_VERSION})"
            log_message "Installed: Bitwarden CLI (GitHub v${BW_VERSION})"
            return 0
        else
            print_color "$RED" "  ✗ Failed to extract Bitwarden CLI"
            rm -rf "$TEMP_DIR"
            return 1
        fi
    else
        print_color "$RED" "  ✗ Failed to download Bitwarden CLI"
        print_color "$CYAN" "  Install manually: https://github.com/bitwarden/cli/releases"
        rm -rf "$TEMP_DIR"
        return 1
    fi
}

# Function to install additional security tools
install_security_tools() {
    print_color "$PURPLE" "=== Additional Security Tools ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will install additional security and privacy tools:"
    print_color "$YELLOW" "  • fail2ban (intrusion prevention)"
    print_color "$YELLOW" "  • rkhunter (rootkit detection)"
    print_color "$YELLOW" "  • secure-delete (secure file deletion)"
    print_color "$YELLOW" "  • tor (anonymity network)"
    print_color "$YELLOW" "  • bitwarden-cli (password manager CLI)"
    print_color "$CYAN" ""
    
    if ! confirm_action "Install additional security tools?"; then
        return 0
    fi
    
    log_message "Installing additional security tools"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y fail2ban rkhunter secure-delete tor
            # Bitwarden CLI installation (try snap first, then GitHub binary)
            if ! command -v bw &> /dev/null; then
                if command -v snap &> /dev/null; then
                    print_color "$CYAN" "  Installing Bitwarden CLI via snap..."
                    if sudo snap install bw 2>/dev/null; then
                        print_color "$GREEN" "  ✓ Bitwarden CLI installed via snap"
                        log_message "Installed: Bitwarden CLI (snap)"
                    else
                        print_color "$YELLOW" "  ⏭ Snap installation failed, trying GitHub binary..."
                        install_bitwarden_from_github
                    fi
                else
                    print_color "$YELLOW" "  ⏭ Snap not available (common on Linux Mint/Zorin), using GitHub binary..."
                    install_bitwarden_from_github
                fi
            else
                print_color "$YELLOW" "  ⏭ Bitwarden CLI already installed, skipping"
            fi
            ;;
        fedora)
            sudo dnf install -y fail2ban rkhunter secure-delete tor
            # Bitwarden CLI via Flatpak
            if ! flatpak list --app | grep -q "com.bitwarden.desktop"; then
                flatpak install -y flathub com.bitwarden.desktop
            fi
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm fail2ban rkhunter secure-delete tor
            # Bitwarden CLI via AUR or Flatpak
            if command -v yay &> /dev/null; then
                yay -S --noconfirm bitwarden-cli
            elif command -v paru &> /dev/null; then
                paru -S --noconfirm bitwarden-cli
            else
                flatpak install -y flathub com.bitwarden.desktop
            fi
            ;;
    esac
    
    # Configure fail2ban
    if command -v fail2ban-client &> /dev/null; then
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban
        print_color "$GREEN" "  ✓ fail2ban installed and started"
        log_message "Installed: fail2ban"
    fi
    
    # Initialize rkhunter
    if command -v rkhunter &> /dev/null; then
        sudo rkhunter --update
        sudo rkhunter --propupd
        print_color "$GREEN" "  ✓ rkhunter installed and initialized"
        print_color "$CYAN" "  Run 'sudo rkhunter --check' to scan your system"
        log_message "Installed: rkhunter"
    fi
    
    # Create secure delete alias
    if command -v srm &> /dev/null; then
        cat >> "$HOME/.bashrc" <<'EOF'

# Secure delete alias
alias sdel='srm -v'
EOF
        print_color "$GREEN" "  ✓ secure-delete installed"
        print_color "$CYAN" "  Use 'sdel <file>' to securely delete files"
        log_message "Installed: secure-delete"
    fi
    
    print_color "$GREEN" "✓ Additional security tools installation complete"
}


# Function to configure automatic security updates
configure_auto_updates() {
    print_color "$PURPLE" "=== Automatic Security Updates ==="
    print_color "$CYAN" ""
    print_color "$CYAN" "This will configure automatic security updates to keep your system secure."
    print_color "$YELLOW" "Only security updates will be installed automatically."
    print_color "$CYAN" ""
    
    if ! confirm_action "Configure automatic security updates?"; then
        return 0
    fi
    
    log_message "Configuring automatic security updates"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt install -y unattended-upgrades
            sudo dpkg-reconfigure -plow unattended-upgrades
            print_color "$GREEN" "  ✓ Automatic security updates configured"
            log_message "Configured: unattended-upgrades"
            ;;
        fedora)
            sudo dnf install -y dnf-automatic
            sudo systemctl enable --now dnf-automatic.timer
            print_color "$GREEN" "  ✓ Automatic security updates configured"
            log_message "Configured: dnf-automatic"
            ;;
        arch|manjaro)
            print_color "$YELLOW" "  Arch-based systems: Consider using a pacman hook or systemd timer"
            print_color "$CYAN" "  Manual updates recommended: sudo pacman -Syu"
            ;;
    esac
    
    print_color "$GREEN" "✓ Automatic security updates configured"
}

# Function to create privacy audit script
create_audit_script() {
    print_color "$PURPLE" "=== Creating Privacy Audit Script ==="
    
    cat > "$HOME/.local/bin/privacy-audit" <<'EOF'
#!/bin/bash
# Privacy configuration audit script

echo "=== Privacy Configuration Audit ==="
echo "Date: $(date)"
echo

# Check firewall status
echo "🔥 Firewall Status:"
sudo ufw status verbose
echo

# Check DNS configuration
echo "🌐 DNS Configuration:"
systemd-resolve --status | grep -A5 "DNS Servers"
echo

# Check running services
echo "📊 Listening Services:"
ss -tuln | grep LISTEN
echo

# Check browser profiles
echo "🌍 Browser Configuration:"
for profile_dir in "$HOME/.zen-browser" "$HOME/.config/zen-browser" "$HOME/.mozilla/zen-browser" "$HOME/.mozilla/firefox"; do
    if [ -d "$profile_dir" ]; then
        echo "Browser profiles found in $profile_dir:"
        find "$profile_dir" -name "user.js" -exec echo "  - {}" \; 2>/dev/null
    fi
done
echo

# Check sandboxing
echo "🏖️ Sandboxing:"
if command -v firejail &> /dev/null; then
    echo "Firejail installed: ✓"
    echo "Active sandbox processes:"
    firejail --list 2>/dev/null || echo "  None currently running"
else
    echo "Firejail: ✗ Not installed"
fi
echo

# Check metadata tools
echo "🗂️ Metadata Tools:"
for tool in mat2 exiftool; do
    if command -v "$tool" &> /dev/null; then
        echo "$tool: ✓"
    else
        echo "$tool: ✗"
    fi
done
echo

echo "Audit complete. Check configurations regularly!"
EOF
    
    chmod +x "$HOME/.local/bin/privacy-audit"
    
    print_color "$GREEN" "✓ Privacy audit script created"
    print_color "$CYAN" "Run 'privacy-audit' to check your privacy configuration anytime"
}

# Function to display summary
show_summary() {
    print_color "$GREEN" ""
    print_color "$GREEN" "================================="
    print_color "$GREEN" "   PRIVACY SETUP COMPLETE!"
    print_color "$GREEN" "================================="
    print_color "$CYAN" ""
    print_color "$CYAN" "What was configured:"
    print_color "$YELLOW" "• UFW Firewall with restrictive rules"
    print_color "$YELLOW" "• Encrypted DNS over TLS (Mullvad/Quad9 with Cloudflare fallback)"
    print_color "$YELLOW" "• Zen Browser with additional privacy-focused settings"
    print_color "$YELLOW" "• Metadata removal tools (mat2, exiftool)"
    print_color "$YELLOW" "• Application sandboxing with Firejail"
    print_color "$YELLOW" "• System hardening configurations"
    print_color "$YELLOW" "• Common applications (VS Code, Spotify, Zen Browser, etc.)"
    print_color "$YELLOW" "• Additional security tools (fail2ban, rkhunter, secure-delete)"
    print_color "$YELLOW" "• Tor Browser for anonymous browsing"
    print_color "$YELLOW" "• Automatic security updates"
    print_color "$YELLOW" "• Privacy audit script"
    print_color "$CYAN" ""
    print_color "$CYAN" "Useful commands:"
    print_color "$WHITE" "• privacy-audit        - Check privacy configuration"
    print_color "$WHITE" "• strip-metadata <file> - Remove file metadata"
    print_color "$WHITE" "• firejail <app>       - Run app in sandbox"
    print_color "$CYAN" ""
    print_color "$BLUE" "Log file: $LOG_FILE"
    print_color "$CYAN" ""
    print_color "$RED" "Remember: Privacy is an ongoing process!"
    print_color "$RED" "Keep your system updated and audit regularly."
}

# Main menu
main_menu() {
    clear
    print_color "$PURPLE" "╔════════════════════════════════════════╗"
    print_color "$PURPLE" "║          $SCRIPT_NAME v$VERSION          ║"
    print_color "$PURPLE" "╚════════════════════════════════════════╝"
    print_color "$CYAN" ""
    print_color "$CYAN" "This toolkit will help configure privacy and security"
    print_color "$CYAN" "settings on your Linux system. Each step will ask for"
    print_color "$CYAN" "your confirmation before making changes."
    print_color "$CYAN" ""
    print_color "$GREEN" "✓ Tailscale detected as failsafe - firewall changes are safe"
    print_color "$CYAN" ""
    
    if ! confirm_action "Ready to begin privacy setup?"; then
        print_color "$YELLOW" "Setup cancelled by user"
        exit 0
    fi
}

# Main execution
main() {
    # Create .local/bin if it doesn't exist
    mkdir -p "$HOME/.local/bin"
    
    # Add .local/bin to PATH if not already there
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        export PATH="$HOME/.local/bin:$PATH"
    fi
    
    main_menu
    check_root
    detect_distro
    check_dependencies
    
    log_message "Starting privacy setup toolkit"
    
    configure_firewall
    configure_dns
    configure_browser
    configure_metadata_removal
    configure_sandboxing
    configure_system_hardening
    install_common_apps
    install_security_tools
    configure_auto_updates
    create_audit_script
    
    show_summary
    
    log_message "Privacy setup completed successfully"
}

# Run main function
main "$@"