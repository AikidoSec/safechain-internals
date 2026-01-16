#!/bin/bash
set -euo pipefail

# =============================================================================
# macOS Package Signing and Notarization Script
# =============================================================================
# 
# This script signs and notarizes a macOS PKG installer package with Apple's notarization service. 
# The script handles the complete workflow from signing to notarization and stapling.
#
# Usage:
#   ./sign-and-notarize-package.sh <path-to-package.pkg>
#
# Prerequisites:
# - Package file must exist at the specified path
# - For signing: DEV_ID_INSTALLER_SHA must be set
# - For notarization: APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, APPLE_TEAM_ID
# - macOS development tools (xcrun, pkgutil, productsign, etc.)
#
# Environment Variables:
# - DEV_ID_INSTALLER_SHA: Developer ID Installer certificate SHA (required for signing)
# - APPLE_ID: Apple Developer account email (required for notarization)
# - APPLE_APP_SPECIFIC_PASSWORD: App-specific password for notarization (required)
# - APPLE_TEAM_ID: Apple Developer Team ID (required for notarization)
# - KEYCHAIN_PATH: Path to keychain containing certificates
#
# Exit Codes:
#   0 - Success
#   1 - Error (with descriptive message)
# =============================================================================

# Source shared utilities for logging and common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/utils.sh"

# =============================================================================
# Environment Validation Functions
# =============================================================================

# Check notarization environment
# Verifies that all required environment variables for Apple notarization are set
check_notarization_environment() {
    log_info "Checking notarization environment..."
    
    # Validate that all required notarization environment variables are present
    if ! validate_env_vars "APPLE_ID" "APPLE_APP_SPECIFIC_PASSWORD" "APPLE_TEAM_ID"; then
        log_error "Notarization environment variables not set"
        log_error "Set APPLE_ID, APPLE_APP_SPECIFIC_PASSWORD, and APPLE_TEAM_ID to enable notarization"
        return 1
    else
        log_success "Notarization environment variables are set"
        return 0
    fi
}

# =============================================================================
# Package Signing Functions
# =============================================================================

# Sign PKG
# Executes the PKG signing script to sign the installer package
sign_pkg() {
    local pkg_path="$1"
    
    log_info "Signing PKG..."
    
    # Verify the PKG signing script exists
    if [ ! -f "$SCRIPT_DIR/sign-package.sh" ]; then
        log_error "PKG signing script not found"
        return 1
    fi
    
    # Ensure the script is executable
    chmod +x "$SCRIPT_DIR/sign-package.sh"
    
    # Execute the PKG signing script with the package path
    if "$SCRIPT_DIR/sign-package.sh" "$pkg_path"; then
        log_success "PKG signing completed successfully"
        return 0
    else
        log_error "PKG signing failed"
        return 1
    fi
}

# =============================================================================
# Package Signing and Notarization Functions
# =============================================================================

# Check if PKG is signed
# Uses pkgutil to verify if the package has a valid signature
is_pkg_signed() {
    local pkg_path="$1"
    
    if pkgutil --check-signature "$pkg_path" 2>/dev/null | grep -q "Status: signed"; then
        return 0  # Package is signed
    else
        return 1  # Package is not signed
    fi
}

# Notarize PKG
# Submits the package to Apple's notarization service and staples the result
notarize_pkg() {
    local pkg_path="$1"
    
    log_info "Checking PKG for notarization..."
    
    # Verify the package file exists before attempting notarization
    if [ ! -f "$pkg_path" ]; then
        log_error "PKG file not found for notarization"
        return 1
    fi
    
    # Only notarize if the package is signed (Apple requirement)
    if is_pkg_signed "$pkg_path"; then
        log_info "PKG is signed, proceeding with notarization..."
        
        # Verify the notarization script exists
        if [ ! -f "$SCRIPT_DIR/notarize-package.sh" ]; then
            log_error "PKG notarization script not found"
            return 1
        fi
        
        # Ensure the script is executable
        chmod +x "$SCRIPT_DIR/notarize-package.sh"
        
        # Execute notarization with package type and path
        if "$SCRIPT_DIR/notarize-package.sh" pkg "$pkg_path"; then
            log_success "PKG notarization completed"
            return 0
        else
            log_error "PKG notarization failed"
            return 1
        fi
    else
        log_warn "PKG is not signed, skipping notarization"
        log_warn "Note: Unsigned PKG files cannot be notarized by Apple"
        log_warn "Users may see security warnings when installing"
        return 1
    fi
}

# =============================================================================
# Package Status and Reporting Functions
# =============================================================================

# Get PKG status
# Determines the current status of the package (signed, notarized, stapled)
get_pkg_status() {
    local pkg_path="$1"
    local notarize="$2"
    
    if [ ! -f "$pkg_path" ]; then
        echo "Not found"
        return
    fi
    
    if is_pkg_signed "$pkg_path"; then
        if [ "$notarize" = true ]; then
            # Check if notarization was stapled to the package
            if xcrun stapler validate "$pkg_path" 2>/dev/null; then
                echo "Signed, notarized and stapled"
            else
                echo "Signed, notarized (stapling may have failed)"
            fi
        else
            echo "Signed, not notarized"
        fi
    else
        echo "Unsigned (not notarized)"
    fi
}

# Display package summary
# Shows a comprehensive summary of the package including size and status
display_package_summary() {
    local pkg_path="$1"
    local notarize="$2"
    
    log_info "Package Summary"
    
    if [ -f "$pkg_path" ]; then
        # Get package file size in human-readable format
        local pkg_size
        pkg_size=$(ls -lh "$pkg_path" | awk '{print $5}')
        local pkg_status
        pkg_status=$(get_pkg_status "$pkg_path" "$notarize")
        
        # Display package information
        log_success "PKG: $pkg_path ($pkg_size)"
        echo "   Status: $pkg_status"
        
        # Warn about unsigned packages
        if [ "$pkg_status" = "Unsigned (not notarized)" ]; then
            log_warn "Note: Users may see security warnings when installing"
        fi
    else
        log_error "No PKG file found"
    fi
}

# =============================================================================
# Main Execution
# =============================================================================

# Main execution function
# Orchestrates the complete package signing and notarization workflow
main() {
    # Validate arguments
    if [ $# -lt 1 ]; then
        log_error "Usage: $0 <path-to-package.pkg>"
        exit 1
    fi
    
    local pkg_path="$1"
    
    echo "Signing and notarizing macOS package..."
    echo "Package: $pkg_path"
    echo ""
    
    # Verify the package file exists
    if [ ! -f "$pkg_path" ]; then
        log_error "Package file not found: $pkg_path"
        exit 1
    fi
    
    # Determine if notarization should be enabled based on environment
    NOTARIZE=false
    if check_notarization_environment; then
        NOTARIZE=true
    fi
    
    echo "Configuration:"
    echo "  Package: $pkg_path"
    echo "  Notarization: $NOTARIZE"
    echo ""
    
    # Step 1: Sign the PKG if not already signed
    echo "=== Signing PKG ==="
    if is_pkg_signed "$pkg_path"; then
        log_info "PKG is already signed, skipping signing step"
    else
        if ! sign_pkg "$pkg_path"; then
            exit 1
        fi
    fi
    
    # Step 2: Notarize the package if enabled
    if [ "$NOTARIZE" = true ]; then
        echo ""
        echo "=== Notarizing PKG ==="
        notarize_pkg "$pkg_path"
    fi
    
    echo ""
    
    # Step 3: Display final summary
    echo "=== Package Summary ==="
    display_package_summary "$pkg_path" "$NOTARIZE"
    
    echo ""
    log_success "Package signing and notarization completed"
}

# Execute the main function with all arguments
main "$@"
