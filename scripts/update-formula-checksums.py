#!/usr/bin/env python3
"""
Update Homebrew formula with SHA256 checksums for both architectures.

Usage:
    python3 update-formula-checksums.py <formula_file> <amd64_sha> <arm64_sha>
"""

import re
import sys


def update_formula_checksums(formula_file: str, amd64_sha: str, arm64_sha: str) -> None:
    """
    Update the Homebrew formula file with the provided checksums.
    
    Args:
        formula_file: Path to the formula file
        amd64_sha: SHA256 checksum for amd64 architecture
        arm64_sha: SHA256 checksum for arm64 architecture
    """
    with open(formula_file, "r") as f:
        content = f.read()
    
    # Update amd64 checksum (in intel block)
    def replace_amd64(match):
        return match.group(1) + amd64_sha + match.group(3)
    
    content = re.sub(
        r'(if Hardware::CPU\.intel\?.*?sha256 ")([^"]+)(")',
        replace_amd64,
        content,
        flags=re.DOTALL
    )
    
    # Update arm64 checksum (in arm block)
    def replace_arm64(match):
        return match.group(1) + arm64_sha + match.group(3)
    
    content = re.sub(
        r'(if Hardware::CPU\.arm\?.*?sha256 ")([^"]+)(")',
        replace_arm64,
        content,
        flags=re.DOTALL
    )
    
    # Fallback: simple replacements if regex didn't work
    content = content.replace('sha256 "REPLACE_WITH_ACTUAL_SHA256"', f'sha256 "{amd64_sha}"', 1)
    content = content.replace('sha256 "REPLACE_WITH_ACTUAL_SHA256"', f'sha256 "{arm64_sha}"', 1)
    
    with open(formula_file, "w") as f:
        f.write(content)


def main():
    """Main entry point."""
    if len(sys.argv) != 4:
        print("Usage: update-formula-checksums.py <formula_file> <amd64_sha> <arm64_sha>", file=sys.stderr)
        sys.exit(1)
    
    formula_file = sys.argv[1]
    amd64_sha = sys.argv[2]
    arm64_sha = sys.argv[3]
    
    try:
        update_formula_checksums(formula_file, amd64_sha, arm64_sha)
        print(f"Successfully updated checksums in {formula_file}")
    except Exception as e:
        print(f"Error updating formula: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

