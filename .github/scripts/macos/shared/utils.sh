#!/bin/bash
# Shared utilities for macOS scripts
# This file should be sourced by other scripts: source .github/scripts/macos/shared/utils.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() { echo -e "$1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_debug() { echo -e "${BLUE}🔍 $1${NC}"; }

# Check if file exists and is readable
check_file_exists() {
    local file_path="$1"
    local description="${2:-File}"
    
    if [ ! -f "$file_path" ]; then
        log_error "$description not found: $file_path"
        return 1
    fi
    
    if [ ! -r "$file_path" ]; then
        log_error "$description not readable: $file_path"
        return 1
    fi
    
    return 0
}

# Check prerequisites
check_prerequisites() {
    local binary_path="$1"
    log_info "Checking prerequisites..."
    
    if ! check_file_exists "$binary_path" "Binary"; then
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Validate required environment variables
validate_env_vars() {
    local missing_vars=()
    
    for var in "$@"; do
        if [ -z "${!var:-}" ]; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        log_error "Missing required environment variables: ${missing_vars[*]}"
        return 1
    fi
    
    return 0
}

# Display binary information
display_binary_info() {
    local binary_path="$1"
    log_info "Binary information:"
    
    echo "Architecture:"
    file "$binary_path"
    
    echo "Architecture details:"
    lipo -info "$binary_path" 2>/dev/null || echo "lipo info not available"
    
    echo "Size:"
    ls -lh "$binary_path"
}

# Extract JSON field from notary response
extract_json_field() {
    local json_data="$1"
    local field_name="$2"
    
    echo "$json_data" | /usr/bin/python3 -c "import json,sys; print(json.load(sys.stdin).get('$field_name',''))"
}

# Clean up temporary files
cleanup_temp_files() {
    local files=("$@")
    
    log_info "Cleaning up temporary files..."
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file"
            log_debug "Removed: $file"
        fi
    done
    log_success "Cleanup completed"
}