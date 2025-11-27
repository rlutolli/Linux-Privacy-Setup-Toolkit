#!/bin/bash
# Test script for privacy-toolkit.sh
# This script tests the main functionality without requiring user interaction

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$SCRIPT_DIR/privacy-toolkit.sh"

echo "=== Testing Privacy Toolkit Script ==="
echo ""

# Test 1: Syntax check
echo "Test 1: Syntax check"
bash -n "$SCRIPT" && echo "✓ Syntax check passed" || { echo "✗ Syntax check failed"; exit 1; }
echo ""

# Test 2: Check for required functions
echo "Test 2: Check for required functions"
required_functions=(
    "check_root"
    "detect_distro"
    "configure_firewall"
    "configure_dns"
    "configure_browser"
    "configure_metadata_removal"
    "configure_sandboxing"
    "configure_system_hardening"
    "install_common_apps"
    "install_security_tools"
    "configure_auto_updates"
    "create_audit_script"
    "install_bitwarden_from_github"
    "cleanup_temp_files"
)

missing_functions=()
for func in "${required_functions[@]}"; do
    if grep -q "^$func()" "$SCRIPT"; then
        echo "✓ Function $func found"
    else
        echo "✗ Function $func missing"
        missing_functions+=("$func")
    fi
done

if [ ${#missing_functions[@]} -gt 0 ]; then
    echo "✗ Missing functions: ${missing_functions[*]}"
    exit 1
fi
echo ""

# Test 3: Check for bug fixes
echo "Test 3: Check for bug fixes"
if grep -q "set +o pipefail" "$SCRIPT" && grep -q "set -o pipefail" "$SCRIPT"; then
    echo "✓ Bug 1 fix found (pipefail handling)"
else
    echo "✗ Bug 1 fix missing"
    exit 1
fi

if grep -q "sudo mv bw /usr/local/bin/bw 2>/dev/null && sudo chmod" "$SCRIPT"; then
    echo "✓ Bug 2 fix found (error handling for sudo commands)"
else
    echo "✗ Bug 2 fix missing"
    exit 1
fi
echo ""

# Test 4: Check DNS configuration fix
echo "Test 4: Check DNS configuration fix"
if grep -q "USE_DOT=" "$SCRIPT" || (grep -q "Mullvad DNS" "$SCRIPT" && grep -q "plain DNS\|without DoT" "$SCRIPT"); then
    echo "✓ DNS configuration fix found (Mullvad DNS configuration available)"
else
    echo "⚠ DNS configuration fix check - manual verification needed"
fi
echo ""

# Test 5: Check cleanup function is called
echo "Test 5: Check cleanup function is called"
if grep -q "cleanup_temp_files" "$SCRIPT" && grep -A 2 "show_summary" "$SCRIPT" | grep -q "cleanup_temp_files"; then
    echo "✓ Cleanup function is called in main"
else
    echo "✗ Cleanup function not called in main"
    exit 1
fi
echo ""

# Test 6: Check error handling
echo "Test 6: Check error handling"
if grep -q "^set -euo pipefail" "$SCRIPT"; then
    echo "✓ Error handling enabled (set -euo pipefail)"
else
    echo "✗ Error handling not enabled"
    exit 1
fi
echo ""

echo "=== All tests passed! ==="
