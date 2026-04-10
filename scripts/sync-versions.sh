#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<EOF
Usage: $(basename "$0") [--version <X.Y.Z> | --dev]

Updates all version locations in the repository.

Options:
  --version X.Y.Z   Set an explicit release version (e.g. 1.2.5)
  --dev             Generate a dev version as 0.0.<unix-timestamp>

Exactly one of --version or --dev must be provided.
EOF
  exit 1
}

VERSION=""
DEV=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --dev)     DEV=true; shift ;;
    *)         usage ;;
  esac
done

if $DEV; then
  [[ -n "$VERSION" ]] && { echo "Error: --version and --dev are mutually exclusive"; exit 1; }
  VERSION="0.0.$(date +%s)"
elif [[ -z "$VERSION" ]]; then
  echo "Error: --version or --dev is required"
  usage
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be numeric X.Y.Z, got: $VERSION"
  exit 1
fi

echo "Syncing all versions to $VERSION"
echo ""

sed_inplace() {
  sed -i.bak -E "$1" "$2"
  rm -f "$2.bak"
}

update() {
  echo "  -> $1"
  shift
  for expr in "$@"; do
    sed_inplace "$expr" "$PREV_FILE"
  done
}

PREV_FILE="$REPO_ROOT/internal/version/version.go"
update "$PREV_FILE" \
  "s/(Version[[:space:]]+= \")[^\"]+(\")$/\1${VERSION}\2/"

PREV_FILE="$REPO_ROOT/Cargo.toml"
update "$PREV_FILE" \
  "s/^(version = \")([^\"]+)(\".*# keep in sync with GH releases)/\1${VERSION}\3/"

echo "  -> $REPO_ROOT/Cargo.lock"
(cd "$REPO_ROOT" && cargo update --workspace)

PREV_FILE="$REPO_ROOT/packaging/macos/xcode/l4-proxy/Project.dist.yml"
update "$PREV_FILE" \
  "s/(MARKETING_VERSION: ).+/\1${VERSION}/" \
  "s/(CURRENT_PROJECT_VERSION: ).+/\1${VERSION}/"

PREV_FILE="$REPO_ROOT/packaging/macos/xcode/l4-proxy/Project.dev.yml"
update "$PREV_FILE" \
  "s/(MARKETING_VERSION: ).+/\1${VERSION}/" \
  "s/(CURRENT_PROJECT_VERSION: ).+/\1${VERSION}/"

PREV_FILE="$REPO_ROOT/packaging/macos/xcode/l7-proxy/project.yml"
update "$PREV_FILE" \
  "s/(MARKETING_VERSION: ).+/\1${VERSION}/" \
  "s/(CURRENT_PROJECT_VERSION: ).+/\1${VERSION}/"

PREV_FILE="$REPO_ROOT/ui/build/windows/msix/app_manifest.xml"
update "$PREV_FILE" \
  "s/([[:space:]]Version=\")[^\"]+(\")/\1${VERSION}\2/"

PREV_FILE="$REPO_ROOT/ui/build/config.yml"
update "$PREV_FILE" \
  "s/(  version: \")[^\"]+(\".*)$/\1${VERSION}\2/"

PREV_FILE="$REPO_ROOT/ui/build/windows/info.json"
update "$PREV_FILE" \
  "s/(\"file_version\": \")[^\"]+(\")/\1${VERSION}\2/" \
  "s/(\"ProductVersion\": \")[^\"]+(\")/\1${VERSION}\2/"

PREV_FILE="$REPO_ROOT/ui/build/windows/nsis/wails_tools.nsh"
update "$PREV_FILE" \
  "s/(INFO_PRODUCTVERSION \")[^\"]+(\")$/\1${VERSION}\2/"

PREV_FILE="$REPO_ROOT/ui/build/darwin/Info.plist"
update "$PREV_FILE" \
  "/CFBundleShortVersionString/{n;s|<string>[^<]*</string>|<string>${VERSION}</string>|;}" \
  "/CFBundleVersion/{n;s|<string>[^<]*</string>|<string>${VERSION}</string>|;}"

PREV_FILE="$REPO_ROOT/ui/build/darwin/Info.dev.plist"
update "$PREV_FILE" \
  "/CFBundleShortVersionString/{n;s|<string>[^<]*</string>|<string>${VERSION}</string>|;}" \
  "/CFBundleVersion/{n;s|<string>[^<]*</string>|<string>${VERSION}</string>|;}"

PREV_FILE="$REPO_ROOT/ui/build/windows/wails.exe.manifest"
update "$PREV_FILE" \
  "s/(name=\"com\.aikido[^\"]*\" version=\")[^\"]+(\")/\1${VERSION}\2/"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=$VERSION" >> "$GITHUB_OUTPUT"
fi

echo ""
echo "Done. All versions set to $VERSION"
