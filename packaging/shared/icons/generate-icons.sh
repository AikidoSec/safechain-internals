#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVG_FILE="$SCRIPT_DIR/SafeChain.svg"

if [ ! -f "$SVG_FILE" ]; then
    echo "Error: SafeChain.svg not found at $SVG_FILE"
    exit 1
fi

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed."
        echo "Install with: $2"
        exit 1
    fi
}

generate_icns() {
    echo "Generating macOS .icns file..."
    
    check_command "rsvg-convert" "brew install librsvg"
    check_command "iconutil" "(built-in on macOS)"
    
    ICONSET_DIR="$SCRIPT_DIR/SafeChain.iconset"
    rm -rf "$ICONSET_DIR"
    mkdir -p "$ICONSET_DIR"
    
    echo "  Generating 16x16..."
    rsvg-convert -w 16 -h 16 "$SVG_FILE" -o "$ICONSET_DIR/icon_16x16.png"
    echo "  Generating 16x16@2x..."
    rsvg-convert -w 32 -h 32 "$SVG_FILE" -o "$ICONSET_DIR/icon_16x16@2x.png"
    
    echo "  Generating 32x32..."
    rsvg-convert -w 32 -h 32 "$SVG_FILE" -o "$ICONSET_DIR/icon_32x32.png"
    echo "  Generating 32x32@2x..."
    rsvg-convert -w 64 -h 64 "$SVG_FILE" -o "$ICONSET_DIR/icon_32x32@2x.png"
    
    echo "  Generating 128x128..."
    rsvg-convert -w 128 -h 128 "$SVG_FILE" -o "$ICONSET_DIR/icon_128x128.png"
    echo "  Generating 128x128@2x..."
    rsvg-convert -w 256 -h 256 "$SVG_FILE" -o "$ICONSET_DIR/icon_128x128@2x.png"
    
    echo "  Generating 256x256..."
    rsvg-convert -w 256 -h 256 "$SVG_FILE" -o "$ICONSET_DIR/icon_256x256.png"
    echo "  Generating 256x256@2x..."
    rsvg-convert -w 512 -h 512 "$SVG_FILE" -o "$ICONSET_DIR/icon_256x256@2x.png"
    
    echo "  Generating 512x512..."
    rsvg-convert -w 512 -h 512 "$SVG_FILE" -o "$ICONSET_DIR/icon_512x512.png"
    echo "  Generating 512x512@2x..."
    rsvg-convert -w 1024 -h 1024 "$SVG_FILE" -o "$ICONSET_DIR/icon_512x512@2x.png"
    
    iconutil -c icns "$ICONSET_DIR" -o "$SCRIPT_DIR/SafeChain.icns"
    rm -rf "$ICONSET_DIR"
    
    echo "Created: $SCRIPT_DIR/SafeChain.icns"
}

generate_ico() {
    echo "Generating Windows .ico file..."
    
    check_command "rsvg-convert" "brew install librsvg (macOS) or apt install librsvg2-bin (Linux)"
    check_command "convert" "brew install imagemagick (macOS) or apt install imagemagick (Linux)"
    
    TMP_DIR="$SCRIPT_DIR/tmp_ico"
    rm -rf "$TMP_DIR"
    mkdir -p "$TMP_DIR"
    
    for SIZE in 16 24 32 48 64 128 256; do
        echo "  Generating ${SIZE}x${SIZE}..."
        rsvg-convert -w $SIZE -h $SIZE "$SVG_FILE" -o "$TMP_DIR/icon_${SIZE}.png"
    done
    
    convert "$TMP_DIR/icon_16.png" "$TMP_DIR/icon_24.png" "$TMP_DIR/icon_32.png" \
            "$TMP_DIR/icon_48.png" "$TMP_DIR/icon_64.png" "$TMP_DIR/icon_128.png" \
            "$TMP_DIR/icon_256.png" "$SCRIPT_DIR/SafeChain.ico"
    
    rm -rf "$TMP_DIR"
    
    echo "Created: $SCRIPT_DIR/SafeChain.ico"
}

generate_png() {
    echo "Generating PNG files for various uses..."
    
    check_command "rsvg-convert" "brew install librsvg (macOS) or apt install librsvg2-bin (Linux)"
    
    for SIZE in 16 32 48 64 128 256 512 1024; do
        echo "  Generating ${SIZE}x${SIZE}..."
        rsvg-convert -w $SIZE -h $SIZE "$SVG_FILE" -o "$SCRIPT_DIR/SafeChain-${SIZE}.png"
    done
    
    echo "Created PNG files in $SCRIPT_DIR"
}

case "${1:-all}" in
    icns)
        generate_icns
        ;;
    ico)
        generate_ico
        ;;
    png)
        generate_png
        ;;
    all)
        generate_icns
        generate_ico
        generate_png
        ;;
    *)
        echo "Usage: $0 [icns|ico|png|all]"
        echo "  icns  - Generate macOS .icns file"
        echo "  ico   - Generate Windows .ico file"
        echo "  png   - Generate PNG files at various sizes"
        echo "  all   - Generate all formats (default)"
        exit 1
        ;;
esac

echo ""
echo "Icon generation complete!"
