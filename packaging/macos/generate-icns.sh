#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SVG_FILE="$PROJECT_DIR/packaging/shared/resources/SafeChain.svg"
OUTPUT_DIR="$SCRIPT_DIR/app-bundle/Contents/Resources"

if [ ! -f "$SVG_FILE" ]; then
    echo "Error: SVG file not found at $SVG_FILE" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

ICONSET_DIR="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET_DIR"
trap "rm -rf '$(dirname "$ICONSET_DIR")'" EXIT

echo "Generating icon sizes from SVG..."

generate_png() {
    local size=$1
    local output=$2
    
    if command -v rsvg-convert &> /dev/null; then
        rsvg-convert -w "$size" -h "$size" "$SVG_FILE" -o "$output"
    elif command -v inkscape &> /dev/null; then
        inkscape -w "$size" -h "$size" "$SVG_FILE" -o "$output" 2>/dev/null
    elif command -v convert &> /dev/null; then
        convert -background none -density 300 -resize "${size}x${size}" "$SVG_FILE" "$output"
    elif command -v qlmanage &> /dev/null; then
        local temp_png="$(mktemp).png"
        qlmanage -t -s "$size" -o "$(dirname "$temp_png")" "$SVG_FILE" 2>/dev/null || true
        if [ -f "${SVG_FILE}.png" ]; then
            mv "${SVG_FILE}.png" "$output"
        else
            echo "Warning: qlmanage failed, creating placeholder" >&2
            sips -z "$size" "$size" "$SVG_FILE" --out "$output" 2>/dev/null || {
                echo "Error: No SVG conversion tool available" >&2
                echo "Please install one of: librsvg, inkscape, or imagemagick" >&2
                exit 1
            }
        fi
    else
        echo "Error: No SVG conversion tool available" >&2
        echo "Please install one of: librsvg (brew install librsvg), inkscape, or imagemagick" >&2
        exit 1
    fi
}

generate_png 16 "$ICONSET_DIR/icon_16x16.png"
generate_png 32 "$ICONSET_DIR/icon_16x16@2x.png"
generate_png 32 "$ICONSET_DIR/icon_32x32.png"
generate_png 64 "$ICONSET_DIR/icon_32x32@2x.png"
generate_png 128 "$ICONSET_DIR/icon_128x128.png"
generate_png 256 "$ICONSET_DIR/icon_128x128@2x.png"
generate_png 256 "$ICONSET_DIR/icon_256x256.png"
generate_png 512 "$ICONSET_DIR/icon_256x256@2x.png"
generate_png 512 "$ICONSET_DIR/icon_512x512.png"
generate_png 1024 "$ICONSET_DIR/icon_512x512@2x.png"

echo "Converting iconset to icns..."
iconutil -c icns "$ICONSET_DIR" -o "$OUTPUT_DIR/AppIcon.icns"

if [ -f "$OUTPUT_DIR/AppIcon.icns" ]; then
    echo "✓ Successfully created $OUTPUT_DIR/AppIcon.icns"
else
    echo "Error: Failed to create icns file" >&2
    exit 1
fi
