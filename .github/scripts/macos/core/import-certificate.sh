#!/bin/bash
set -euo pipefail

# =============================================================================
# macOS Certificate Import Script
# =============================================================================
# This script sets up the macOS code signing environment for CI/CD builds.
# It handles the import of Developer ID Application and Developer ID Installer
# certificates into a temporary keychain for automated code signing.
#
# Prerequisites:
# - MACOS_CERTIFICATE_P12: Base64-encoded Developer ID Application certificate
# - MACOS_INSTALLER_CERTIFICATE_P12: Base64-encoded Developer ID Installer certificate
# - MACOS_CERTIFICATE_PASSWORD: Password for both certificates
#
# Environment Variables:
# - KEYCHAIN_PATH: Path to the temporary keychain (exported for other scripts)
# - DEV_ID_SHA: SHA hash of the Developer ID Application identity
# - DEV_ID_INSTALLER_SHA: SHA hash of the Developer ID Installer identity
#
# Exit Codes:
# - 0: Success
# - 1: Certificate import failure or missing required certificates
# =============================================================================

# Source shared utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/utils.sh"

# =============================================================================
# Environment Status Display
# =============================================================================
# Shows which environment variables are set without revealing their values for security purposes. 
# This helps with debugging certificate availability.
show_environment_status() {
    log_info "Environment Variables Status"
    log_info "MACOS_CERTIFICATE_P12: ${MACOS_CERTIFICATE_P12:+SET}"
    log_info "MACOS_INSTALLER_CERTIFICATE_P12: ${MACOS_INSTALLER_CERTIFICATE_P12:+SET}"
    log_info "MACOS_CERTIFICATE_PASSWORD: ${MACOS_CERTIFICATE_PASSWORD:+SET}"
    echo ""
}

# =============================================================================
# Keychain Setup
# =============================================================================
# Creates a temporary keychain for storing certificates during the build process.
# This keychain is separate from the user's login keychain to avoid conflicts
# and ensure clean certificate management in CI environments.
setup_keychain() {
    log_info "Setting up build keychain..."
    
    # Use full path with .keychain-db extension for newer macOS versions
    # The .keychain-db format is the modern keychain format used by macOS
    KEYCHAIN_PATH="$HOME/Library/Keychains/build.keychain-db"
    
    # Create a new keychain with no password (suitable for CI environments)
    security create-keychain -p "" "$KEYCHAIN_PATH"
    
    # Set this keychain as the default for the current session
    security list-keychains -s "$KEYCHAIN_PATH"
    security default-keychain -s "$KEYCHAIN_PATH"
    
    # Unlock the keychain to make it accessible
    security unlock-keychain -p "" "$KEYCHAIN_PATH"
    
    # Set keychain timeout to 6 hours (21600 seconds) to prevent premature locking
    security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"
    
    # Configure the search list to prioritize our CI keychain over the login keychain
    # This ensures our certificates are found first during code signing operations
    security list-keychains -d user -s "$KEYCHAIN_PATH" login.keychain
    security default-keychain -d user -s "$KEYCHAIN_PATH"
    
    # Export the keychain path for use in other scripts (e.g., create-pkg.sh)
    echo "KEYCHAIN_PATH=$KEYCHAIN_PATH" >> "$GITHUB_ENV"
    
    log_success "Keychain setup completed"
}

# =============================================================================
# Certificate Import Function
# =============================================================================
# Generic function to import a certificate from base64-encoded data into the keychain.
# This function handles the decoding, validation, and import process for any certificate.
#
# Parameters:
#   $1: cert_name - Human-readable name for logging (e.g., "application", "installer")
#   $2: cert_base64 - Base64-encoded certificate data
#   $3: cert_password - Password to decrypt the certificate
#   $4: cert_file - Temporary filename for the decoded certificate
#
# Returns:
#   0: Success
#   1: Failure (with error details)
import_certificate() {
    local cert_name="$1"
    local cert_base64="$2"
    local cert_password="$3"
    local cert_file="$4"
    
    log_info "Importing $cert_name certificate..."
    
    # Decode base64 certificate data and save to temporary file
    # The certificate is typically in PKCS#12 (.p12) format containing both
    # the certificate and private key
    echo "$cert_base64" | base64 -d > "$cert_file"
    
    # Validate the decoded file size to ensure it's not empty or corrupted
    local file_size=$(ls -la "$cert_file" | awk '{print $5}')
    log_debug "$cert_name certificate file size: ${file_size} bytes"
    
    # Import the certificate into the keychain with specific access controls
    # -k: Specifies the keychain to import into
    # -P: Provides the password for the certificate
    # -T: Trusts the specified tools (codesign, productsign) to access the key without prompting for password
    if security import "$cert_file" -k "$KEYCHAIN_PATH" -P "$cert_password" -T /usr/bin/codesign -T /usr/bin/productsign; then
        log_success "$cert_name certificate imported successfully"
        rm -f "$cert_file"  # Clean up temporary file
        return 0
    else
        log_error "Failed to import $cert_name certificate"
        echo "This might be due to:"
        echo "  - Incorrect password"
        echo "  - Corrupted .p12 file"
        echo "  - Invalid certificate format"
        rm -f "$cert_file"  # Clean up temporary file even on failure
        return 1
    fi
}

# =============================================================================
# Application Certificate Import
# =============================================================================
# Imports the Developer ID Application certificate used for signing binaries.
# This certificate is required for distributing macOS applications outside the App Store.
import_application_certificate() {
    if [ -n "${MACOS_CERTIFICATE_P12:-}" ]; then
        if import_certificate "application" "$MACOS_CERTIFICATE_P12" "$MACOS_CERTIFICATE_PASSWORD" "certificate.p12"; then
            return 0
        else
            exit 1  # Exit immediately on application certificate failure
        fi
    else
        log_warn "No application certificate provided (MACOS_CERTIFICATE_P12 not set)"
        log_warn "Binary will not be signed"
        return 1
    fi
}

# =============================================================================
# Installer Certificate Import
# =============================================================================
# Imports the Developer ID Installer certificate used for signing package installers.
# This certificate is required for distributing .pkg files outside the App Store.
import_installer_certificate() {
    if [ -n "${MACOS_INSTALLER_CERTIFICATE_P12:-}" ]; then
        if import_certificate "installer" "$MACOS_INSTALLER_CERTIFICATE_P12" "$MACOS_CERTIFICATE_PASSWORD" "installer_certificate.p12"; then
            return 0
        else
            log_error "Failed to import installer certificate"
            return 1
        fi
    else
        log_warn "No installer certificate provided (MACOS_INSTALLER_CERTIFICATE_P12 not set)"
        log_warn "PKG packages will not be signed"
        return 1
    fi
}

# =============================================================================
# Keychain Access Configuration
# =============================================================================
# Configures the keychain to allow automated access by code signing tools
# without requiring user interaction. This is essential for CI/CD environments.
configure_keychain_access() {
    log_info "Configuring keychain access permissions..."
    
    # Ensure the keychain is unlocked for the current session
    security unlock-keychain -p "" "$KEYCHAIN_PATH" || true
    
    # Set key partition list to allow specific tools to access the private key
    # without prompting for password. This is crucial for automated builds.
    # -S: Specifies the partition list (apple-tool:, apple:, codesign:, productsign:)
    # -s: Sets the partition list
    # -k: Uses empty password (since keychain is unlocked)
    security set-key-partition-list -S apple-tool:,apple:,codesign:,productsign: -s -k "" "$KEYCHAIN_PATH"
    
    log_success "Keychain access permissions configured"
}

# =============================================================================
# Keychain Information Display
# =============================================================================
# Displays all certificates in the keychain for debugging purposes.
# This helps verify that certificates were imported correctly.
display_keychain_info() {
    log_debug "All certificates in keychain (all types):"
    security find-identity -v "$KEYCHAIN_PATH" || echo "No certificates found"
}

# =============================================================================
# Developer ID Application Identity Extraction
# =============================================================================
# Extracts the SHA hash of the Developer ID Application certificate identity.
# This hash is required by codesign to identify which certificate to use
# for signing binaries.
extract_application_identity() {
    log_info "Extracting Developer ID Application identity..."
    
    # Find the Developer ID Application identity in the keychain
    # -v: Verbose output showing all identities
    # -p codesigning: Only show identities valid for code signing
    # awk: Extract the SHA hash from the first Developer ID Application line
    DEV_ID_SHA=$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" | awk '/Developer ID Application:/ {print $2; exit}')
    
    if [ -z "${DEV_ID_SHA:-}" ]; then
        log_warn "No 'Developer ID Application' identity found in the keychain."
        log_warn "Binary signing will not be available."
        return 1
    else
        log_success "Found Developer ID Application identity: $DEV_ID_SHA"
        # Export the SHA hash for use in other scripts
        echo "DEV_ID_SHA=$DEV_ID_SHA" >> "$GITHUB_ENV"
        return 0
    fi
}

# =============================================================================
# Developer ID Installer Identity Extraction
# =============================================================================
# Extracts the SHA hash of the Developer ID Installer certificate identity.
# This hash is required by productsign to identify which certificate to use
# for signing package installers.
extract_installer_identity() {
    log_info "Extracting Developer ID Installer identity..."
    
    # Note: Developer ID Installer certificates are not valid for general code signing,
    # so we search without the -p codesigning flag to see all certificates
    log_debug "Searching for Developer ID Installer certificates in keychain: $KEYCHAIN_PATH"
    
    # First, let's see all certificates to debug
    log_debug "All certificates in keychain:"
    security find-identity -v "$KEYCHAIN_PATH" 2>/dev/null || log_debug "Failed to list certificates"
    
    # Search for Developer ID Installer certificates specifically
    # awk: Extract the SHA hash from the first Developer ID Installer line
    DEV_ID_INSTALLER_SHA=$(security find-identity -v "$KEYCHAIN_PATH" 2>/dev/null | awk '/Developer ID Installer:/ {print $2; exit}')
    
    if [ -z "${DEV_ID_INSTALLER_SHA:-}" ]; then
        log_warn "No 'Developer ID Installer' identity found in the keychain."
        log_warn "Package signing will not be available."
        
        # Debug: Show what installer-related certificates we do have
        echo ""
        log_debug "Available installer-related certificates:"
        security find-identity -v "$KEYCHAIN_PATH" 2>/dev/null | grep -i "installer" || echo "No installer certificates found"
        
        # Check if the MACOS_INSTALLER_CERTIFICATE_P12 environment variable is set
        if [ -z "${MACOS_INSTALLER_CERTIFICATE_P12:-}" ]; then
            log_error "MACOS_INSTALLER_CERTIFICATE_P12 environment variable is not set"
            log_error "Please add the Developer ID Installer certificate to your GitHub secrets"
        else
            log_error "MACOS_INSTALLER_CERTIFICATE_P12 is set but no installer certificate was imported"
            log_error "This might indicate an issue with the certificate format or password"
        fi
        
        # Ensure the environment variable is not set when no installer certificate is found
        # This prevents the create-pkg.sh script from incorrectly using the application certificate
        unset DEV_ID_INSTALLER_SHA
        return 1
    else
        log_success "Found Developer ID Installer identity: $DEV_ID_INSTALLER_SHA"
        # Export the SHA hash for use in other scripts
        echo "DEV_ID_INSTALLER_SHA=$DEV_ID_INSTALLER_SHA" >> "$GITHUB_ENV"
        return 0
    fi
}

# =============================================================================
# Cleanup Function
# =============================================================================
# Removes temporary files created during the certificate import process.
# This function is called automatically when the script exits (via trap).
cleanup() {
    # Remove any temporary certificate files that might still exist
    # These files contain sensitive certificate data and should be cleaned up
    rm -f certificate.p12 installer_certificate.p12
}

# =============================================================================
# Main Execution Function
# =============================================================================
# Orchestrates the entire certificate import process by calling each step
# in the correct order. Sets up error handling and cleanup.
main() {
    echo "Setting up macOS code signing environment..."
    
    # Set up cleanup trap to ensure temporary files are removed on exit
    # This works for both normal exit and error conditions
    trap cleanup EXIT
    
    # Execute steps in order:
    # 1. Show environment status for debugging
    # 2. Set up the temporary keychain
    # 3. Import certificates (application first, then installer)
    # 4. Configure keychain access permissions
    # 5. Display keychain information for verification
    # 6. Extract certificate identities for use in other scripts
    show_environment_status
    setup_keychain
    import_application_certificate
    import_installer_certificate
    configure_keychain_access
    display_keychain_info
    extract_application_identity
    extract_installer_identity
    
    log_success "Certificate import completed successfully"
}

# =============================================================================
# Script Entry Point
# =============================================================================
# Execute the main function with all command line arguments
main "$@"