#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$SRCROOT/../../../.." && pwd)"
RUST_BIN_SRC="$PROJECT_ROOT/target/release/endpoint-protection-l7-proxy"
RUST_BIN_DST="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH/endpoint-protection-l7-proxy-bin"

pushd "$PROJECT_ROOT" >/dev/null
cargo build --release -p endpoint-protection-l7-proxy
popd >/dev/null

mkdir -p "$(dirname "$RUST_BIN_DST")"
cp "$RUST_BIN_SRC" "$RUST_BIN_DST"
chmod +x "$RUST_BIN_DST"

if [[ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" ]]; then
  codesign --force \
    --sign "$EXPANDED_CODE_SIGN_IDENTITY" \
    --identifier "$PRODUCT_BUNDLE_IDENTIFIER" \
    --entitlements "$SRCROOT/entitlements/protected.entitlements" \
    --timestamp=none \
    "$RUST_BIN_DST"
else
  echo "warning: EXPANDED_CODE_SIGN_IDENTITY is empty; rust binary was not signed"
fi
