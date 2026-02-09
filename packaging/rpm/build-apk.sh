#!/bin/bash

set -e

VERSION=""
ARCH=""
RPM_FILE=""
OUTPUT_DIR="./dist"

while getopts "v:a:r:o:h" opt; do
    case $opt in
        v) VERSION="$OPTARG" ;;
        a) ARCH="$OPTARG" ;;
        r) RPM_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h)
            echo "Usage: $0 -v VERSION -a ARCH -r RPM_FILE [-o OUTPUT_DIR]"
            echo "  -v VERSION      Version number (e.g., 1.0.0)"
            echo "  -a ARCH         Architecture (arm64 or amd64)"
            echo "  -r RPM_FILE     Path to the RPM file to convert"
            echo "  -o OUTPUT_DIR   Output directory (default: ./dist)"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Error: VERSION is required (-v)" >&2
    exit 1
fi

if [ -z "$ARCH" ]; then
    echo "Error: ARCH is required (-a)" >&2
    exit 1
fi

if [ -z "$RPM_FILE" ]; then
    echo "Error: RPM_FILE is required (-r)" >&2
    exit 1
fi

if [ "$VERSION" = "dev" ]; then
    PKG_VERSION="0.0.0"
else
    PKG_VERSION="$VERSION"
fi

case "$ARCH" in
    amd64)  APK_ARCH="x86_64" ;;
    arm64)  APK_ARCH="aarch64" ;;
    *)
        echo "Error: Unsupported architecture: $ARCH (expected amd64 or arm64)" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RPM_FILE="$(cd "$(dirname "$RPM_FILE")" && pwd)/$(basename "$RPM_FILE")"
OUTPUT_DIR="$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)"

if [ ! -f "$RPM_FILE" ]; then
    echo "Error: RPM file not found at $RPM_FILE" >&2
    exit 1
fi

echo "Converting RPM to Alpine APK for SafeChain Ultimate v$VERSION"
echo "  Architecture: $ARCH ($APK_ARCH)"
echo "  RPM file: $RPM_FILE"
echo "  Output directory: $OUTPUT_DIR"

BUILD_DIR="$(mktemp -d)"
trap "rm -rf '$BUILD_DIR'" EXIT

echo "Using temporary build directory: $BUILD_DIR"

PKG_ROOT="$BUILD_DIR/pkg"
mkdir -p "$PKG_ROOT"

echo "Extracting RPM contents..."
cd "$PKG_ROOT"
rpm2cpio "$RPM_FILE" | cpio -idm 2>/dev/null

echo "Creating APK metadata..."
cat > "$PKG_ROOT/.PKGINFO" <<EOF
pkgname=safechain-ultimate
pkgver=$PKG_VERSION-r0
pkgdesc=SafeChain Ultimate - Security Agent by Aikido Security
url=https://aikido.dev
builddate=$(date +%s)
size=$(du -sb "$PKG_ROOT" | awk '{print $1}')
arch=$APK_ARCH
license=AGPL-3.0-or-later
origin=safechain-ultimate
EOF

mkdir -p "$PKG_ROOT/.scripts"

cat > "$PKG_ROOT/.scripts/.pre-install" <<'EOF'
#!/bin/sh
if command -v rc-service >/dev/null 2>&1; then
    rc-service safechain-ultimate stop 2>/dev/null || true
fi
EOF

cat > "$PKG_ROOT/.scripts/.post-install" <<'POSTEOF'
#!/bin/sh
mkdir -p /var/log/aikidosecurity/safechainultimate

if command -v rc-update >/dev/null 2>&1; then
    rc-update add safechain-ultimate default 2>/dev/null || true
    rc-service safechain-ultimate start 2>/dev/null || true
fi

echo ""
echo "SafeChain Ultimate has been installed successfully!"
echo "  Binaries: /opt/aikidosecurity/safechainultimate/bin"
echo "  Logs:     /var/log/aikidosecurity/safechainultimate"
POSTEOF

cat > "$PKG_ROOT/.scripts/.pre-deinstall" <<'EOF'
#!/bin/sh
if command -v rc-service >/dev/null 2>&1; then
    rc-service safechain-ultimate stop 2>/dev/null || true
    rc-update del safechain-ultimate default 2>/dev/null || true
fi
EOF

chmod 755 "$PKG_ROOT/.scripts/.pre-install"
chmod 755 "$PKG_ROOT/.scripts/.post-install"
chmod 755 "$PKG_ROOT/.scripts/.pre-deinstall"

echo "Building APK package..."

cd "$BUILD_DIR"

tar -czf "$BUILD_DIR/data.tar.gz" -C "$PKG_ROOT" \
    --exclude='.PKGINFO' \
    --exclude='.scripts' \
    .

tar -czf "$BUILD_DIR/control.tar.gz" -C "$PKG_ROOT" \
    .PKGINFO \
    .scripts/

cat "$BUILD_DIR/control.tar.gz" "$BUILD_DIR/data.tar.gz" > "$BUILD_DIR/combined.tar.gz"

OUTPUT_APK="$OUTPUT_DIR/SafeChainUltimate-$VERSION-$ARCH.apk"
cp "$BUILD_DIR/combined.tar.gz" "$OUTPUT_APK"

echo ""
echo "✓ APK package built successfully: $OUTPUT_APK"
echo ""

CHECKSUM=$(sha256sum "$OUTPUT_APK" | awk '{print $1}')
echo "SHA256: $CHECKSUM"
echo "$CHECKSUM" > "$OUTPUT_APK.sha256"
echo ""

SIZE=$(du -h "$OUTPUT_APK" | awk '{print $1}')
echo "Package size: $SIZE"

exit 0
