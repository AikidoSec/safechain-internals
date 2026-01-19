#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SVG_FILE="$SCRIPT_DIR/SafeChain.svg"

echo "Generating icon files from SafeChain.svg..."

if ! command -v rsvg-convert &> /dev/null && ! command -v magick &> /dev/null && ! command -v convert &> /dev/null; then
    echo "Error: Neither rsvg-convert nor ImageMagick found."
    echo "Install with: brew install librsvg imagemagick"
    exit 1
fi

PNG_DIR="$SCRIPT_DIR/icon_pngs"
rm -rf "$PNG_DIR"
mkdir -p "$PNG_DIR"

generate_png() {
    local size=$1
    local output="$PNG_DIR/icon_${size}x${size}.png"
    
    if command -v rsvg-convert &> /dev/null; then
        rsvg-convert -w "$size" -h "$size" "$SVG_FILE" -o "$output"
    elif command -v magick &> /dev/null; then
        magick -background none -resize "${size}x${size}" "$SVG_FILE" "$output"
    else
        convert -background none -resize "${size}x${size}" "$SVG_FILE" "$output"
    fi
    echo "  Generated ${size}x${size} PNG"
}

echo "Generating PNG files..."
for size in 16 32 48 64 128 256 512 1024; do
    generate_png $size
done

if [[ "$OSTYPE" == "darwin"* ]]; then
    echo ""
    echo "Generating macOS .icns file..."
    
    ICONSET_DIR="$SCRIPT_DIR/SafeChain.iconset"
    rm -rf "$ICONSET_DIR"
    mkdir -p "$ICONSET_DIR"
    
    sips -z 16 16 "$PNG_DIR/icon_16x16.png" --out "$ICONSET_DIR/icon_16x16.png" > /dev/null
    sips -z 32 32 "$PNG_DIR/icon_32x32.png" --out "$ICONSET_DIR/icon_16x16@2x.png" > /dev/null
    sips -z 32 32 "$PNG_DIR/icon_32x32.png" --out "$ICONSET_DIR/icon_32x32.png" > /dev/null
    sips -z 64 64 "$PNG_DIR/icon_64x64.png" --out "$ICONSET_DIR/icon_32x32@2x.png" > /dev/null
    sips -z 128 128 "$PNG_DIR/icon_128x128.png" --out "$ICONSET_DIR/icon_128x128.png" > /dev/null
    sips -z 256 256 "$PNG_DIR/icon_256x256.png" --out "$ICONSET_DIR/icon_128x128@2x.png" > /dev/null
    sips -z 256 256 "$PNG_DIR/icon_256x256.png" --out "$ICONSET_DIR/icon_256x256.png" > /dev/null
    sips -z 512 512 "$PNG_DIR/icon_512x512.png" --out "$ICONSET_DIR/icon_256x256@2x.png" > /dev/null
    sips -z 512 512 "$PNG_DIR/icon_512x512.png" --out "$ICONSET_DIR/icon_512x512.png" > /dev/null
    sips -z 1024 1024 "$PNG_DIR/icon_1024x1024.png" --out "$ICONSET_DIR/icon_512x512@2x.png" > /dev/null
    
    iconutil -c icns "$ICONSET_DIR" -o "$SCRIPT_DIR/SafeChain.icns"
    echo "  Generated SafeChain.icns"
    
    rm -rf "$ICONSET_DIR"
fi

echo ""
echo "Generating Windows .ico file..."
if command -v magick &> /dev/null; then
    magick "$PNG_DIR/icon_16x16.png" \
           "$PNG_DIR/icon_32x32.png" \
           "$PNG_DIR/icon_48x48.png" \
           "$PNG_DIR/icon_64x64.png" \
           "$PNG_DIR/icon_128x128.png" \
           "$PNG_DIR/icon_256x256.png" \
           "$SCRIPT_DIR/SafeChain.ico"
    echo "  Generated SafeChain.ico"
elif command -v convert &> /dev/null; then
    convert "$PNG_DIR/icon_16x16.png" \
            "$PNG_DIR/icon_32x32.png" \
            "$PNG_DIR/icon_48x48.png" \
            "$PNG_DIR/icon_64x64.png" \
            "$PNG_DIR/icon_128x128.png" \
            "$PNG_DIR/icon_256x256.png" \
            "$SCRIPT_DIR/SafeChain.ico"
    echo "  Generated SafeChain.ico"
else
    echo "  Warning: ImageMagick not found, skipping .ico generation"
    echo "  Install with: brew install imagemagick"
fi

echo ""
echo "Generating background.png for macOS installer..."
if command -v rsvg-convert &> /dev/null; then
    rsvg-convert -w 80 -h 80 "$SVG_FILE" -o "$SCRIPT_DIR/background.png"
    echo "  Generated background.png"
elif command -v magick &> /dev/null; then
    magick -background none -resize 80x80 "$SVG_FILE" "$SCRIPT_DIR/background.png"
    echo "  Generated background.png"
elif command -v convert &> /dev/null; then
    convert -background none -resize 80x80 "$SVG_FILE" "$SCRIPT_DIR/background.png"
    echo "  Generated background.png"
else
    cp "$PNG_DIR/icon_64x64.png" "$SCRIPT_DIR/background.png"
    echo "  Generated background.png (from 64x64)"
fi

rm -rf "$PNG_DIR"

echo ""
echo "Icon generation complete!"
ls -la "$SCRIPT_DIR"/*.icns "$SCRIPT_DIR"/*.ico "$SCRIPT_DIR"/*.png 2>/dev/null || true
