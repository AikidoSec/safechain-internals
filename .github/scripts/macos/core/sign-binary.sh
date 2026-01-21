#!/bin/bash
set -euo pipefail

# =============================================================================
# macOS Binary Signing Script
# =============================================================================
# This script signs a macOS binary with a Developer ID Application certificate for distribution outside the Mac App Store. 
#The signing process includes:
# 1. Prerequisites validation (certificate, binary existence)
# 2. Code signing with Developer ID Application certificate
# 3. Signature verification
# 4. Gatekeeper assessment (informational)
# 5. Team identifier verification
#
# Prerequisites:
# - Run import-certificate.sh first to set up the signing certificate
# - Binary must exist at dist/aikido-local-scanner
# - Valid Developer ID Application certificate in build.keychain
#
# Environment Variables Required:
# - DEV_ID_SHA: SHA hash of the Developer ID Application certificate
# - APPLE_TEAM_ID: Apple Developer Team ID for verification
# =============================================================================

# Configuration
BINARY_PATH=$1
ENTITLEMENTS_PATH="$(dirname "${BASH_SOURCE[0]}")/safechain-ultimate.entitlements"

# Source shared utilities for logging and validation functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../shared/utils.sh"

# =============================================================================
# Function: check_prerequisites
# =============================================================================
# Validates that all required components are available before signing:
# - Environment variables for certificate and team ID
# - Binary file exists at the expected path
#
# Returns: 0 if all prerequisites are met, 1 otherwise
# =============================================================================
check_prerequisites() {
    log_info "Checking signing prerequisites..."
    
    # Validate required environment variables are set
    if ! validate_env_vars "DEV_ID_SHA" "APPLE_TEAM_ID"; then
        log_error "Run import-certificate.sh first"
        exit 1
    fi
    
    # Ensure the binary file exists before attempting to sign
    if ! check_file_exists "$BINARY_PATH" "Binary"; then
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# =============================================================================
# Function: sign_binary
# =============================================================================
# Signs the binary with the Developer ID Application certificate.
# Uses the specific identity and keychain created during certificate import.
#
# Signing options explained:
# --force: Overwrite any existing signature
# --sign: Use the specified certificate identity
# --timestamp: Add a timestamp to the signature for long-term validity
# --options runtime: Enable hardened runtime (required for notarization)
# --entitlements: Apply specific entitlements for the application
# --keychain: Use the custom keychain containing the certificate
#
# Returns: 0 if signing succeeds, 1 otherwise
# =============================================================================
sign_binary() {
    log_info "Signing binary with Developer ID Application certificate..."
    
    # Use the specific identity and keychain we created
    if codesign --force --sign "$DEV_ID_SHA" --timestamp --options runtime \
        --entitlements "$ENTITLEMENTS_PATH" \
        --keychain build.keychain "$BINARY_PATH"; then
        log_success "Binary signed successfully"
        return 0
    else
        log_error "Binary signing failed"
        return 1
    fi
}

# =============================================================================
# Function: verify_signature
# =============================================================================
# Verifies that the binary was signed correctly by checking the signature integrity and validity. 
# This is a critical step to ensure the signing process completed successfully.
#
# Verification options:
# --verify: Verify the signature
# --strict: Use strict verification (reject invalid signatures)
# --verbose=2: Provide detailed output for debugging
#
# Returns: 0 if verification passes, 1 otherwise
# =============================================================================
verify_signature() {
    log_info "Verifying binary signature..."
    
    if codesign --verify --strict --verbose=2 "$BINARY_PATH"; then
        log_success "Signature verification passed"
        return 0
    else
        log_error "Signature verification failed"
        return 1
    fi
}

# =============================================================================
# Function: run_gatekeeper_assessment
# =============================================================================
# Runs a Gatekeeper assessment on the signed binary. This is informational and helps verify that the binary would pass Gatekeeper checks on other systems. 
# Note that unstapled binaries may show non-zero exit codes, which is often normal and expected.
#
# Assessment options:
# --assess: Assess the binary for Gatekeeper compatibility
# --type execute: Specify that this is an executable file
# --verbose=4: Provide maximum verbosity for debugging
# =============================================================================
run_gatekeeper_assessment() {
    log_info "Running Gatekeeper assessment (informational)..."
    
    if spctl --assess --type execute --verbose=4 "$BINARY_PATH"; then
        log_success "Gatekeeper assessment passed"
    else
        log_warn "Gatekeeper assessment non-zero (often normal for unstapled binaries)"
    fi
}

# =============================================================================
# Function: verify_team_identifier
# =============================================================================
# Verifies that the team identifier in the signed binary matches the expected team ID. 
# This is crucial for notarization, as the notary service requires the binary to be signed with a certificate from the same team that submits it for notarization.
#
# This function:
# 1. Extracts the TeamIdentifier from the signed binary
# 2. Compares it with the expected APPLE_TEAM_ID
# 3. Fails if there's a mismatch (prevents notarization issues)
#
# Returns: 0 if team identifiers match, 1 otherwise
# =============================================================================
verify_team_identifier() {
    log_info "Verifying team identifier..."
    
    # Extract the TeamIdentifier from the signed binary
    local team_in_bin
    team_in_bin=$(codesign -dvv "$BINARY_PATH" 2>&1 | awk -F= '/TeamIdentifier/ {print $2}')
    
    echo "TeamIdentifier in binary: $team_in_bin"
    echo "Expected TeamIdentifier: $APPLE_TEAM_ID"
    
    # Verify the team identifiers match
    if [ "$team_in_bin" != "$APPLE_TEAM_ID" ]; then
        log_error "Team mismatch: binary signed for '$team_in_bin' but notary submit uses '$APPLE_TEAM_ID'."
        log_error "Sign with a Developer ID Application cert from the same team you use for notarytool."
        exit 1
    fi
    
    log_success "Team identifier verification passed"
}

# =============================================================================
# Function: main
# =============================================================================
# Main execution function that orchestrates the entire signing process.
# Executes each step in sequence and provides clear feedback on progress.
#
# Process flow:
# 1. Check prerequisites (certificate, binary existence)
# 2. Sign the binary with Developer ID Application certificate
# 3. Verify the signature integrity
# 4. Run Gatekeeper assessment (informational)
# 5. Display binary information for verification
# 6. Verify team identifier matches expected value
#
# The script exits with error code 1 if any step fails, ensuring that signing issues are caught early in the CI/CD pipeline.
# =============================================================================
main() {
    echo "Signing macOS binary..."
    
    # Execute steps in sequence
    check_prerequisites
    sign_binary
    verify_signature
    run_gatekeeper_assessment
    display_binary_info "$BINARY_PATH"
    verify_team_identifier
    
    log_success "Binary signing completed successfully"
}

# Execute the main function with all command line arguments
main "$@"