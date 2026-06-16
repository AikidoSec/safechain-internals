#!/bin/bash

RUN_DIR="/Library/Application Support/AikidoSecurity/EndpointProtection/run"
APP="/Applications/Aikido Endpoint Protection.app"
HEALTHY="$APP/Contents/Resources/scripts/healthy"

status=0

ok()   { printf "  \033[32m[OK]\033[0m   %s\n" "$1"; }
fail() { printf "  \033[31m[FAIL]\033[0m %s%s\n" "$1" "${2:+ — $2}"; status=1; }

echo "Aikido Endpoint Protection — Doctor"
echo "===================================="

echo
echo "Installation"

[ -d "$APP" ] \
  && ok "App installed" \
  || fail "App installed" "not found at $APP"

if [ -x "$HEALTHY" ]; then
  "$HEALTHY" &>/dev/null \
    && ok "Health check" \
    || fail "Health check" "returned non-zero"
else
  fail "Health check" "script not found or not executable"
fi

echo
echo "Run directory"

files=(
  config.json
  endpoint-protection-combined-ca.pem
  endpoint-protection-git-combined-ca.pem
  endpoint-protection-node-original-extra-ca-certs.txt
  endpoint-protection-openssl-combined-ca.pem
  endpoint-protection-pip-combined-ca.pem
  endpoint-protection-pip-original-cert-path.txt
  endpoint-protection-proxy-ca-crt.pem
  endpoint-protection-ruby-combined-ca.pem
)

for f in "${files[@]}"; do
  [ -f "$RUN_DIR/$f" ] \
    && ok "$f" \
    || fail "$f" "missing"
done

echo
echo "Package manager CA configuration"

expect_config() {
  local name="$1" actual="$2" expected="$3"
  # npm returns the string "null" when unset
  [ "$actual" = "$expected" ] \
    && ok "$name" \
    || fail "$name" "expected '$expected', got '${actual:-<not set>}'"
}

expect_config "npm cafile" \
  "$(npm config get cafile 2>/dev/null || true)" \
  "$RUN_DIR/endpoint-protection-combined-ca.pem"

expect_config "NODE_EXTRA_CA_CERTS" \
  "${NODE_EXTRA_CA_CERTS:-}" \
  "$RUN_DIR/endpoint-protection-combined-ca.pem"

expect_config "pip global.cert" \
  "$(pip config get global.cert 2>/dev/null || true)" \
  "$RUN_DIR/endpoint-protection-pip-combined-ca.pem"

expect_config "git http.sslCAInfo" \
  "$(git config --global http.sslCAInfo 2>/dev/null || true)" \
  "$RUN_DIR/endpoint-protection-git-combined-ca.pem"

exit "$status"
