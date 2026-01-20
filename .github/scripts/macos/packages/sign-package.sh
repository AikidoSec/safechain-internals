#!/bin/bash
set -euo pipefail

# =============================================================================
# Aikido Local Scanner - macOS Package Signing Script
# =============================================================================
# 
# This script signs a macOS installer package (.pkg) with a Developer ID
# Installer certificate and verifies the signature.
#
# Usage:
#   ./sign-package.sh <path-to-package.pkg>
#
# Prerequisites:
# - macOS build environment
# - Developer ID Installer certificate
# - productsign and pkgutil tools
# - Package file must exist at the specified path
#
# Environment Variables:
#   DEV_ID_INSTALLER_SHA      - Developer ID Installer certificate SHA (required)
#   KEYCHAIN_PATH             - Path to keychain containing certificates
#
# Exit Codes:
#   0 - Success
#   1 - Error (with descriptive message)
# =============================================================================

# Source shared utilities (logging, cleanup, etc.)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/utils.sh"

# =============================================================================
# Signing Identity Resolution
# =============================================================================
# Determines which signing identity to use for package signing.
# Checks for Developer ID Installer certificate in environment variables.
#
# Returns:
#   - Signing identity SHA if found
#   - Empty string if no identity found
#   - Logs error messages for missing certificates
# =============================================================================
get_signing_identity() {
    if [ -n "${DEV_ID_INSTALLER_SHA:-}" ]; then
        log_success "Using Developer ID Installer identity: $DEV_ID_INSTALLER_SHA" >&2
        echo "$DEV_ID_INSTALLER_SHA"
    else
        log_error "No signing identity found, PKG signing is required" >&2
        log_error "Please ensure MACOS_INSTALLER_CERTIFICATE_P12 is set in GitHub secrets" >&2
        echo ""
    fi
}

# =============================================================================
# Network Connectivity Check
# =============================================================================
# Checks network connectivity to Apple's timestamp servers.
# This is important for code signing operations that require timestamping.
#
# Returns:
#   0 - Network connectivity is good
#   1 - Cannot reach Apple's servers
# =============================================================================
check_network_connectivity() {
    log_info "Checking network connectivity to Apple's timestamp servers..."
    
    if ping -c 3 timestamp.apple.com >/dev/null 2>&1; then
        log_success "Network connectivity to Apple's servers appears good"
        return 0
    else
        log_warn "Cannot reach Apple's timestamp servers"
        return 1
    fi
}

# =============================================================================
# Package File Validation
# =============================================================================
# Validates that a PKG file exists and is not empty.
# This function is critical for ensuring PKG files are properly created before
# proceeding with signing, verification, or other operations that require
# a valid PKG file. It prevents errors from propagating through the build pipeline.
# =============================================================================
validate_pkg_file() {
    local pkg_path="$1"
    [ -f "$pkg_path" ] && [ -s "$pkg_path" ]
}

# =============================================================================
# Keychain Access Verification
# =============================================================================
# Verifies that the signing identity is available in the keychain.
# This ensures that productsign can access the required certificate.
#
# Args:
#   $1 - Signing identity (certificate SHA)
#
# Returns:
#   0 - Signing identity found in keychain
#   1 - Signing identity not found
# =============================================================================
verify_keychain_access() {
    local signing_identity="$1"
    
    log_info "Verifying keychain access for productsign..."
    
    # Check for existing productsign processes that might cause conflicts
    if pgrep -f "productsign" > /dev/null; then
        log_warn "Found existing productsign processes, this may cause conflicts"
        pgrep -f "productsign" | xargs ps -o pid,command -p
    fi

    # Use KEYCHAIN_PATH if available, fallback to build.keychain for compatibility
    local keychain_path="${KEYCHAIN_PATH:-build.keychain}"
    
    # Ensure we have the full path to the keychain
    if [[ "$keychain_path" != /* ]]; then
        keychain_path="$HOME/Library/Keychains/$keychain_path-db"
    fi
    
    # Check if the signing identity exists in the keychain
    if security find-identity -v "$keychain_path" | grep -F -q "$signing_identity"; then
        log_success "Signing identity found in keychain"
        return 0
    else
        log_error "Signing identity not found in keychain"
        return 1
    fi
}

# =============================================================================
# Package Signing
# =============================================================================
# Signs the PKG file using productsign with the specified signing identity.
# This is required for notarization and proper macOS security validation.
#
# Args:
#   $1 - Path to PKG file
#   $2 - Signing identity (certificate SHA)
#
# Returns:
#   0 - Package signed successfully
#   1 - Signing failed
# =============================================================================
sign_pkg() {
    local pkg_path="$1"
    local signing_identity="$2"
    
    log_info "Signing PKG..."
    
    # Determine keychain path (prefer env var set by import-certificate.sh)
    local keychain_path="${KEYCHAIN_PATH:-$HOME/Library/Keychains/build.keychain-db}"
    if [[ "$keychain_path" != /* ]]; then
        keychain_path="$HOME/Library/Keychains/${keychain_path}-db"
    fi
    
    # Ensure input PKG exists before attempting to sign
    if ! validate_pkg_file "$pkg_path"; then
        log_error "PKG to sign not found: $pkg_path"
        return 1
    fi
    
    # Warn (do not fail) if keychain is not in search list
    if ! security list-keychains | grep -Fq "$keychain_path"; then
        log_warn "Keychain not in search list: $keychain_path"
    fi
    
    # Create temporary signed package name
    local signed_pkg="signed-$(basename "$pkg_path")"
    rm -f "$signed_pkg"
    
    # Sign the package using productsign
    log_info "Running: productsign --keychain \"$keychain_path\" --sign \"$signing_identity\" \"$pkg_path\" \"$signed_pkg\""
    if productsign --keychain "$keychain_path" \
                   --sign "$signing_identity" \
                   "$pkg_path" \
                   "$signed_pkg"; then
        # Verify the signed package was created successfully
        if validate_pkg_file "$signed_pkg"; then
            mv -f "$signed_pkg" "$pkg_path"
            log_success "PKG signed successfully"
            return 0
        else
            log_error "Signed PKG was not created or empty: $signed_pkg"
            rm -f "$signed_pkg"
            return 1
        fi
    else
        local exit_code=$?
        log_error "productsign failed with exit code $exit_code"
        rm -f "$signed_pkg"
        return $exit_code
    fi
}

# =============================================================================
# Package Signature Verification
# =============================================================================
# Verifies that the PKG file has a valid signature using pkgutil.
# This ensures the package was signed correctly and hasn't been tampered with.
#
# Args:
#   $1 - Path to PKG file
#
# Returns:
#   0 - Signature verification passed
#   1 - Signature verification failed
# =============================================================================
verify_pkg_signature() {
    local pkg_path="$1"
    
    log_info "Verifying PKG signature..."
    
    if pkgutil --check-signature "$pkg_path"; then
        log_success "PKG signature verification passed"
        return 0
    else
        log_error "PKG signature verification failed"
        return 1
    fi
}

# =============================================================================
# Package Signing Orchestration
# =============================================================================
# Orchestrates the complete package signing process including validation,
# signing, and verification. This is the main entry point for package signing.
#
# Args:
#   $1 - Path to PKG file
# =============================================================================
sign_package() {
    local pkg_path="$1"
    local signing_identity="$2"
    
    # Validate signing identity is provided
    if [ -z "$signing_identity" ]; then
        log_error "No signing identity found for PKG"
        log_error "PKG signing is required for notarization"
        log_error "Please ensure MACOS_INSTALLER_CERTIFICATE_P12 is set in GitHub secrets"
        exit 1
    fi
    
    # Validate package path is provided
    if [ -z "$pkg_path" ]; then
        log_error "Package path is required as first argument"
        exit 1
    fi
    
    # Validate package file exists
    if ! validate_pkg_file "$pkg_path"; then
        log_error "Package file not found or empty: $pkg_path"
        exit 1
    fi
    
    echo ""
    echo "=== Signing PKG ==="
    echo "Using signing identity: $signing_identity"
    echo "PKG path: $pkg_path"
    
    # Check network connectivity for timestamping    
    check_network_connectivity
    
    # Verify keychain access before attempting to sign
    if ! verify_keychain_access "$signing_identity"; then
        exit 1
    fi
    
    # Sign the PKG
    if ! sign_pkg "$pkg_path" "$signing_identity"; then
        exit 1
    fi
    
    # Verify the signature
    if ! verify_pkg_signature "$pkg_path"; then
        exit 1
    fi
}

# =============================================================================
# Main Execution Function
# =============================================================================
# Main entry point that orchestrates the package signing process.
#
# Args:
#   $1 - Path to PKG file to sign
# =============================================================================
main() {
    # Validate arguments
    if [ $# -lt 1 ]; then
        log_error "Usage: $0 <path-to-package.pkg>"
        exit 1
    fi
    
    local pkg_path="$1"
    
    echo "Signing macOS PKG installer..."
    echo "Package: $pkg_path"
    
    # Get signing identity from environment
    SIGNING_IDENTITY=$(get_signing_identity)
    
    # Sign the PKG (signing is required for notarization)
    if [ -n "$SIGNING_IDENTITY" ]; then
        sign_package "$pkg_path" "$SIGNING_IDENTITY"
    else
        log_error "No signing identity found, PKG signing is required"
        log_error "Please ensure MACOS_INSTALLER_CERTIFICATE_P12 is set in GitHub secrets"
        exit 1
    fi
    
    # Final success message
    echo ""
    log_success "PKG signing completed: $pkg_path"
    log_success "PKG signing process completed successfully"
}

# Run main function with all arguments
main "$@"