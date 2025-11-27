#!/bin/bash
# Test script for privacy-toolkit.sh
# Run this locally to validate the script before pushing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_FILE="$SCRIPT_DIR/privacy-toolkit.sh"

echo "🧪 Testing Privacy Toolkit Script"
echo "=================================="
echo ""

# Test 1: Syntax check
echo "Test 1: Syntax Check"
if bash -n "$SCRIPT_FILE"; then
    echo "✓ Syntax check passed"
else
    echo "✗ Syntax check failed"
    exit 1
fi
echo ""

# Test 2: Check for required functions
echo "Test 2: Required Functions Check"
required_functions=(
    "check_root"
    "detect_distro"
    "check_dependencies"
    "configure_firewall"
    "configure_dns"
    "configure_browser"
    "configure_metadata_removal"
    "configure_sandboxing"
    "configure_system_hardening"
    "install_common_apps"
    "install_security_tools"
    "configure_auto_updates"
    "configure_performance"
    "create_audit_script"
)

missing_functions=()
for func in "${required_functions[@]}"; do
    if grep -q "^$func()" "$SCRIPT_FILE"; then
        echo "  ✓ $func"
    else
        echo "  ✗ $func (missing)"
        missing_functions+=("$func")
    fi
done

if [ ${#missing_functions[@]} -gt 0 ]; then
    echo "✗ Missing functions: ${missing_functions[*]}"
    exit 1
fi
echo "✓ All required functions present"
echo ""

# Test 3: Check for error handling
echo "Test 3: Error Handling Check"
if grep -q "set -euo pipefail" "$SCRIPT_FILE"; then
    echo "✓ Error handling enabled (set -euo pipefail)"
else
    echo "✗ Error handling not found"
    exit 1
fi
echo ""

# Test 4: Check for logging
echo "Test 4: Logging Check"
if grep -q "log_message" "$SCRIPT_FILE"; then
    echo "✓ Logging function present"
else
    echo "✗ Logging function missing"
    exit 1
fi
echo ""

# Test 5: Check for user confirmation
echo "Test 5: User Confirmation Check"
if grep -q "confirm_action" "$SCRIPT_FILE"; then
    echo "✓ User confirmation function present"
else
    echo "✗ User confirmation function missing"
    exit 1
fi
echo ""

# Test 6: Check for color output
echo "Test 6: Color Output Check"
if grep -q "print_color" "$SCRIPT_FILE"; then
    echo "✓ Color output function present"
else
    echo "✗ Color output function missing"
    exit 1
fi
echo ""

# Test 7: Check for version
echo "Test 7: Version Check"
if grep -q 'VERSION=' "$SCRIPT_FILE"; then
    version=$(grep 'VERSION=' "$SCRIPT_FILE" | head -1 | cut -d'"' -f2)
    echo "✓ Version found: $version"
else
    echo "✗ Version not found"
    exit 1
fi
echo ""

# Test 8: Check for main function
echo "Test 8: Main Function Check"
if grep -q "^main()" "$SCRIPT_FILE"; then
    echo "✓ Main function present"
else
    echo "✗ Main function missing"
    exit 1
fi
echo ""

# Test 9: Check for shebang
echo "Test 9: Shebang Check"
if head -1 "$SCRIPT_FILE" | grep -q "^#!/bin/bash"; then
    echo "✓ Shebang present"
else
    echo "✗ Shebang missing or incorrect"
    exit 1
fi
echo ""

# Test 10: Check for dangerous commands (safety check)
echo "Test 10: Safety Check"
dangerous_patterns=(
    "rm -rf /"
    "rm -rf /home"
    "rm -rf /etc"
    "dd if=/dev/zero"
)

found_dangerous=false
for pattern in "${dangerous_patterns[@]}"; do
    if grep -q "$pattern" "$SCRIPT_FILE"; then
        echo "  ⚠ Warning: Potentially dangerous pattern found: $pattern"
        found_dangerous=true
    fi
done

if [ "$found_dangerous" = false ]; then
    echo "✓ No dangerous patterns found"
else
    echo "⚠ Review dangerous patterns before proceeding"
fi
echo ""

echo "=================================="
echo "✅ All tests passed!"
echo ""
echo "The script is ready to push to GitHub."
echo "GitHub Actions will run additional tests on push."

