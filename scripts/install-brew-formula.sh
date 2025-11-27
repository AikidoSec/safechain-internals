#!/bin/bash
set -e

# Script to install the Homebrew formula for safechain-agent
# This script installs the formula from the local build directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FORMULA_FILE="$PROJECT_ROOT/build/Formula/safechain-agent.rb"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

info() {
    echo -e "${GREEN}✓${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

step() {
    echo -e "${BLUE}→${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    if ! command -v brew &> /dev/null; then
        error "Homebrew is not installed. Please install it from https://brew.sh"
    fi
    
    if [ ! -f "$FORMULA_FILE" ]; then
        error "Formula file not found: $FORMULA_FILE\nRun './scripts/build-brew-formula.sh' first to build the formula."
    fi
    
    info "Prerequisites check passed"
}

# Check if already installed
check_installed() {
    if brew list safechain-agent &>/dev/null; then
        warn "safechain-agent is already installed"
        read -p "Do you want to reinstall? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Installation cancelled"
            exit 0
        fi
        step "Uninstalling existing installation..."
        brew uninstall safechain-agent 2>/dev/null || true
    fi
}

# Install the formula
install_formula() {
    step "Installing safechain-agent from local formula..."
    
    if [ ! -r "$FORMULA_FILE" ]; then
        error "Cannot read formula file: $FORMULA_FILE"
    fi
    
    # Homebrew requires formulae to be in a tap, but we can use a local tap
    # Create a local tap directory structure
    local tap_name="aikido/safechain-agent-local"
    local tap_dir="aikido/homebrew-safechain-agent-local"
    
    # Get Homebrew prefix and tap path
    local brew_prefix
    brew_prefix=$(brew --prefix)
    local tap_path="$brew_prefix/../Library/Taps/$tap_dir"
    
    step "Creating local tap (no GitHub required)..."
    
    # Create tap directory structure manually
    local tap_parent=$(dirname "$tap_path")
    
    # Check if we can write to the parent directory
    if [ ! -w "$tap_parent" ] 2>/dev/null; then
        # Try to create in a writable location
        warn "Cannot write to $tap_parent, trying alternative location..."
        tap_path="$HOME/.homebrew/Library/Taps/$tap_dir"
        tap_parent=$(dirname "$tap_path")
    fi
    
    # Create the tap directory structure
    mkdir -p "$tap_path/Formula" || {
        error "Cannot create tap directory: $tap_path\nPlease check permissions"
    }
    
    # Copy formula to tap
    step "Copying formula to local tap..."
    if [ -w "$tap_path/Formula" ]; then
        cp "$FORMULA_FILE" "$tap_path/Formula/safechain-agent.rb" || {
            error "Cannot copy formula to tap directory"
        }
    elif sudo cp "$FORMULA_FILE" "$tap_path/Formula/safechain-agent.rb" 2>/dev/null; then
        info "Formula copied using sudo"
    else
        error "Cannot write to tap directory: $tap_path/Formula\nPlease check permissions"
    fi
    
    # Add tap using local file path (not GitHub URL)
    # This avoids any GitHub credential prompts
    step "Adding local tap..."
    
    # Use the local file path instead of the tap name to avoid GitHub
    # First, try to add it as a local tap
    if [ -d "$tap_path" ]; then
        # Install directly from the tap path (local file system)
        step "Installing from local tap path..."
        
        # Disable API checks to avoid GitHub
        export HOMEBREW_NO_INSTALL_FROM_API=1
        export HOMEBREW_NO_AUTO_UPDATE=1
        
        # Install using the full path to the formula file in the tap
        if HOMEBREW_NO_INSTALL_FROM_API=1 HOMEBREW_NO_AUTO_UPDATE=1 brew install --build-from-source "$tap_path/Formula/safechain-agent.rb"; then
            info "Successfully installed safechain-agent"
        else
            # Fallback: try adding tap and installing by name
            warn "Direct path install failed, trying tap method..."
            # Create a symlink or use brew tap with file:// protocol
            if brew tap --force "$tap_name" 2>/dev/null || true; then
                if HOMEBREW_NO_INSTALL_FROM_API=1 HOMEBREW_NO_AUTO_UPDATE=1 brew install --build-from-source "$tap_name/safechain-agent"; then
                    info "Successfully installed safechain-agent"
                else
                    error "Failed to install safechain-agent"
                fi
            else
                error "Failed to add tap and install formula"
            fi
        fi
    else
        error "Tap directory was not created successfully"
    fi
}

# Show post-installation information
show_post_install_info() {
    echo ""
    echo "=========================================="
    echo "Installation Complete!"
    echo "=========================================="
    info "safechain-agent has been installed"
    echo ""
    echo "Next steps:"
    echo ""
    echo "1. Start the daemon:"
    echo "   launchctl load ~/Library/LaunchAgents/homebrew.mxcl.safechain-agent.plist"
    echo ""
    echo "2. Check daemon status:"
    echo "   launchctl list | grep safechain-agent"
    echo ""
    echo "3. View logs:"
    echo "   tail -f /usr/local/var/log/safechain-agent.log"
    echo ""
    echo "4. Stop the daemon:"
    echo "   launchctl unload ~/Library/LaunchAgents/homebrew.mxcl.safechain-agent.plist"
    echo ""
    echo "5. Uninstall:"
    echo "   brew uninstall safechain-agent"
    echo ""
}

# Main execution
main() {
    echo "=========================================="
    echo "Installing Homebrew Formula"
    echo "=========================================="
    
    # Check prerequisites
    check_prerequisites
    
    # Check if already installed
    check_installed
    
    # Install the formula
    install_formula
    
    # Show post-installation info
    show_post_install_info
}

# Run main function
main

