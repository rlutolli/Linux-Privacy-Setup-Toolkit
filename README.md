# Linux Privacy Setup Toolkit

A comprehensive privacy and security hardening script for Linux systems with automatic application installation.

## Features

- 🔥 **UFW Firewall Configuration** - Restrictive firewall rules with SSH access
- 🔐 **Encrypted DNS** - Mullvad or Quad9 DNS with Cloudflare fallback
- 🌐 **Browser Privacy** - Zen Browser configuration with additional privacy settings
- 🗂️ **Metadata Removal** - Tools for stripping metadata from files
- 🏖️ **Application Sandboxing** - Firejail for isolating applications
- 🛡️ **System Hardening** - Kernel security parameters and service management
- 📦 **Selective Applications** - Choose from categories: Default (Zen/Brave), Privacy (includes Tor), Development, Communication (Equibop), Media
- 🔒 **Security Tools** - fail2ban, rkhunter, secure-delete, Bitwarden CLI
- ⚡ **Performance Optimizations** - zswap, swap tuning, I/O scheduler, CPU governor
- 🔄 **Auto Updates** - Automatic security updates configuration
- 📊 **Privacy Audit** - Script to check your privacy configuration

## Requirements

- Linux distribution (Ubuntu/Debian, Fedora, or Arch/Manjaro)
- sudo access
- Internet connection

## Installation

### Quick Install

```bash
# Download the script
curl -fsSL https://raw.githubusercontent.com/rlutolli/Linux-Privacy-Setup-Toolkit/main/privacy-toolkit.sh -o privacy-toolkit.sh

# Make it executable
chmod +x privacy-toolkit.sh

# Run it
./privacy-toolkit.sh
```

**Note:** This script requires an interactive terminal for safety. Piping directly to bash won't work.

### Manual Install

1. Clone or download this repository
2. Make the script executable:
   ```bash
   chmod +x privacy-toolkit.sh
   ```
3. Run the script:
   ```bash
   ./privacy-toolkit.sh
   ```

## What It Does

The script will guide you through each step with detailed explanations:

1. **Firewall Setup** - Configures UFW with restrictive rules (allows SSH, blocks incoming by default)
2. **DNS Encryption** - Choose between Mullvad or Quad9 DNS with Cloudflare as fallback
3. **Browser Configuration** - Configures Zen Browser with additional privacy settings
4. **Metadata Tools** - Installs exiftool and mat2 for removing file metadata
5. **Sandboxing** - Installs and configures Firejail for application isolation
6. **System Hardening** - Applies kernel security parameters and optionally disables unnecessary services
7. **Selective Apps** - Choose application categories:
   - Default: Zen Browser and/or Brave Browser
   - Privacy: Browsers + Tor Browser
   - Development: VS Code, GitHub Desktop
   - Communication: Equibop
   - Media: Spotify
   - Custom: Select individual apps
8. **Security Tools** - Installs fail2ban, rkhunter, secure-delete, Bitwarden CLI
9. **Auto Updates** - Configures automatic security updates
10. **Performance Optimizations** - Configures zswap, swap tuning, I/O scheduler optimization, CPU governor
11. **Audit Script** - Creates a `privacy-audit` command to check your setup

## Customizations

- **DNS Providers**: Choose Mullvad (privacy-focused) or Quad9 (security-focused) during setup
- **Services**: Optionally disable bluetooth, cups (printing), avahi-daemon (with warning about P2P applications)
- **Applications**: Selective installation with categories - choose what you need
- **Applications**: The script checks if apps are already installed and skips them

## Useful Commands

After running the script, you'll have access to:

- `privacy-audit` - Check your privacy configuration
- `strip-metadata <file>` - Remove metadata from files
- `firejail <app>` - Run applications in a sandbox
- `sdel <file>` - Securely delete files (overwrites before deletion)
- `sudo rkhunter --check` - Scan for rootkits
- `bw` - Bitwarden CLI for password management

## Notes

- **Tailscale**: If you have Tailscale installed, firewall changes are safe as it uses its own network interface
- **Zen Browser**: The script auto-detects Flatpak installations of Zen Browser
- **Logging**: All actions are logged to `/tmp/privacy_toolkit_*.log`

## Safety

- ✅ Prompts for confirmation before each major change
- ✅ Does not run as root (uses sudo when needed)
- ✅ Logs all actions
- ✅ Can be run multiple times safely (skips already installed/configured items)

## License

This script is provided as-is for privacy and security hardening purposes.

## Contributing

Feel free to fork, modify, and improve this script for your needs.

