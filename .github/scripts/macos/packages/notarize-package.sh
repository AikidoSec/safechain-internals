#!/bin/bash
set -euo pipefail

# =============================================================================
# macOS Package Notarization Script
# =============================================================================
# 
# This script handles the complete notarization process for macOS PKG files.
# Notarization is Apple's security requirement that ensures packages are safe to run on macOS by scanning them for malicious code.
#
# The process involves:
# 1. Validating the package file and its signature
# 2. Submitting the package to Apple's notary service
# 3. Waiting for notarization to complete
# 4. Stapling the notarization ticket to the package
# 5. Validating the final result
#
# Environment Variables Required:
# - APPLE_ID: Your Apple Developer account email
# - APPLE_APP_SPECIFIC_PASSWORD: App-specific password for your Apple ID
# - APPLE_TEAM_ID: Your Apple Developer Team ID
#
# Exit Codes:
# - 0: Success (package notarized and optionally stapled)
# - 1: Error (validation failure, notarization rejected, or stapling failed)
# =============================================================================

# =============================================================================
# Configuration Constants
# =============================================================================
# Maximum number of attempts to staple the package
readonly MAX_STAPLE_ATTEMPTS=3

# Delay in seconds between stapling retry attempts
readonly STAPLE_RETRY_DELAY=5

# Exit code returned by stapler when package is already stapled
readonly STAPLE_ALREADY_STAPLED_ERROR_CODE=73

# =============================================================================
# Input Validation and Setup
# =============================================================================
# Extract command line arguments
PACKAGE_TYPE="${1:-}"
PACKAGE_PATH="${2:-}"

# Determine the script directory and source shared utilities
# This allows the script to be called from any location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/utils.sh"

# Validate that both required arguments are provided
if [[ -z "$PACKAGE_TYPE" || -z "$PACKAGE_PATH" ]]; then
    log_error "Usage: $0 <pkg> <file-path>"
    log_error "Example: $0 pkg aikido-local-scanner.pkg"
    log_error ""
    log_error "Arguments:"
    log_error "  pkg        - Package type (currently only 'pkg' is supported)"
    log_error "  file-path  - Path to the PKG file to notarize"
    exit 1
fi

# Validate package type - currently only PKG files are supported
# This could be extended in the future to support other formats like DMG
if [[ "$PACKAGE_TYPE" != "pkg" ]]; then
    log_error "Package type must be 'pkg', got: $PACKAGE_TYPE"
    log_error "Other package types are not currently supported"
    exit 1
fi

# Verify the package file exists and is accessible
if ! check_file_exists "$PACKAGE_PATH" "Package file"; then
    exit 1
fi

# =============================================================================
# Pre-flight Checks and Package Analysis
# =============================================================================
log_info "Starting macOS package notarization process..."
log_info "Package type: $PACKAGE_TYPE"
log_info "Package path: $PACKAGE_PATH"

# Display package information for debugging and verification
log_info "Pre-flight checks:"
log_info "  Package size: $(ls -lh "$PACKAGE_PATH")"
log_info "  Package type: $(file -b "$PACKAGE_PATH")"

# Check if the PKG file is properly signed
# Signing is required for notarization to succeed
log_info "PKG signature summary:"
if ! pkgutil --check-signature "$PACKAGE_PATH" 2>&1; then
    log_warn "PKG not signed - notarization may fail"
    log_warn "Ensure the package is signed with a valid Developer ID certificate"
fi

# =============================================================================
# Submit Package to Apple's Notary Service
# =============================================================================
log_info "Submitting to notary service (JSON output)…"

# Submit the package to Apple's notary service
# The --wait flag makes the command wait for completion instead of returning immediately 
# JSON output format provides structured data for parsing the result
SUBMIT_JSON=$(xcrun notarytool submit "$PACKAGE_PATH" \
    --apple-id "$APPLE_ID" \
    --password "$APPLE_APP_SPECIFIC_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" \
    --wait \
    --output-format json)

# Display the full JSON response for debugging
echo "$SUBMIT_JSON"

# Extract key information from the JSON response
# These fields are used to determine success and for error reporting
STATUS=$(extract_json_field "$SUBMIT_JSON" "status")
ID=$(extract_json_field "$SUBMIT_JSON" "id")

# =============================================================================
# Handle Notarization Result
# =============================================================================
# Check if notarization was accepted
# "Accepted" means the package passed Apple's security scan
if [[ "$STATUS" != "Accepted" ]]; then
    log_error "Notarization not accepted (status: $STATUS). Fetching detailed log…"
    
    # If we have a submission ID, fetch the detailed log for debugging
    # This helps identify why the notarization failed
    if [[ -n "$ID" ]]; then
        log_info "Fetching detailed notarization log for submission ID: $ID"
        xcrun notarytool log "$ID" \
            --apple-id "$APPLE_ID" \
            --password "$APPLE_APP_SPECIFIC_PASSWORD" \
            --team-id "$APPLE_TEAM_ID" \
            --output-format json | tee notarization-log.json
    fi
    exit 1
fi

log_success "Notarization accepted. Stapling ticket…"

# =============================================================================
# Stapling Functions
# =============================================================================
# Stapling attaches the notarization ticket directly to the package
# This allows the package to be opened without internet connectivity and without users having to manually approve it

# Attempt to staple the package with retries
# Stapling can sometimes fail due to network issues or timing
attempt_stapling() {
    local attempt=1
    
    while [[ $attempt -le $MAX_STAPLE_ATTEMPTS ]]; do
        log_info "Stapling attempt $attempt of $MAX_STAPLE_ATTEMPTS..."
        
        # Attempt to staple the package
        if xcrun stapler staple "$PACKAGE_PATH"; then
            log_success "Stapling completed successfully on attempt $attempt"
            return 0
        fi
        
        # Capture the exit code for error handling
        local staple_exit_code=$?
        log_error "Stapling failed on attempt $attempt with exit code: $staple_exit_code"
        
        # Handle the special case where the package is already stapled
        # Exit code 73 indicates the package was already stapled, which is not an error
        if [[ "$staple_exit_code" -eq $STAPLE_ALREADY_STAPLED_ERROR_CODE ]]; then
            log_warn "Error 73: Checking if package is already stapled..."
            if xcrun stapler validate "$PACKAGE_PATH" 2>/dev/null; then
                log_success "Package appears to already be properly stapled"
                return 0
            fi
        fi
        
        # Wait before retry (except on the last attempt)
        # This helps with transient network or timing issues
        if [[ $attempt -lt $MAX_STAPLE_ATTEMPTS ]]; then
            log_info "Waiting ${STAPLE_RETRY_DELAY} seconds before retry..."
            sleep $STAPLE_RETRY_DELAY
        fi
        
        ((attempt++))
    done
    
    return 1
}

# Validate that stapling was successful
# This checks if the notarization ticket is properly attached
validate_stapling() {
    if xcrun stapler validate "$PACKAGE_PATH"; then
        log_success "Stapling validation passed"
        return 0
    else
        # Validation warnings are common and usually not critical
        log_warn "Stapling validation reported warnings (this may be normal)"
        return 1
    fi
}

# =============================================================================
# Execute Stapling Process
# =============================================================================
# Attempt to staple the package with retry logic
if attempt_stapling; then
    log_success "Stapling process completed successfully"
    # Validate the stapling result (warnings are acceptable)
    validate_stapling
else
    log_error "All stapling attempts failed"
    log_info "Checking final package status..."
    
    # Perform a final status check to see what state the package is in
    log_info "Package notarization status:"
    xcrun stapler validate "$PACKAGE_PATH" 2>&1 || log_warn "Validation failed"
fi

# =============================================================================
# Final Status and Summary
# =============================================================================
log_success "Package notarization process completed"
log_info "Summary:"
log_info "  - Package: $PACKAGE_PATH"
log_info "  - Notarization: $STATUS"