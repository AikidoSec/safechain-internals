#!/bin/bash

RUN_DIR="/Library/Application Support/AikidoSecurity/EndpointProtection/run"
APP="/Applications/Aikido Endpoint Protection.app"
HEALTHY="$APP/Contents/Resources/scripts/healthy"

status=0

ok()   { printf "  \033[32m[OK]\033[0m   %s\n" "$1"; }
fail() { printf "  \033[31m[FAIL]\033[0m %s%s\n" "$1" "${2:+ — $2}"; status=1; }

expect_env() {
  local var="$1" expected="$2"
  local actual="${!var:-}"
  [ "$actual" = "$expected" ] \
    && ok "$var" \
    || fail "$var" "expected '$expected', got '${actual:-<not set>}'"
}

isset_env() {
  local var="$1"
  [ -n "${!var:-}" ] \
    && ok "$var" \
    || fail "$var" "not set"
}

expect_bool() {
  local var="$1"
  local actual="${!var:-}"
  [ "$actual" = "true" ] \
    && ok "$var" \
    || fail "$var" "expected 'true', got '${actual:-<not set>}'"
}

check_gemrc() {
  local gemrc="$HOME/.gemrc"
  if [ ! -f "$gemrc" ]; then
    fail "~/.gemrc" "file not found"
    return
  fi
  local block
  block=$(sed -n '/# aikido-endpoint-ruby-gemrc-start/,/# aikido-endpoint-ruby-gemrc-end/p' "$gemrc")
  if [ -z "$block" ]; then
    fail "~/.gemrc" "Aikido block not found"
    return
  fi
  local cert_path
  cert_path=$(printf '%s\n' "$block" | grep ':ssl_ca_cert:' | sed 's/.*:ssl_ca_cert:[[:space:]]*//')
  if [ -z "$cert_path" ]; then
    fail "~/.gemrc :ssl_ca_cert" "key not found in Aikido block"
    return
  fi
  [ -f "$cert_path" ] \
    && ok "~/.gemrc :ssl_ca_cert" \
    || fail "~/.gemrc :ssl_ca_cert" "cert file not found: $cert_path"
}

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

# Node.js
expect_env NODE_EXTRA_CA_CERTS "$RUN_DIR/endpoint-protection-combined-ca.pem"
expect_env npm_config_cafile   "$RUN_DIR/endpoint-protection-npm-cafile.pem"

# Python
expect_env PIP_CERT                      "$RUN_DIR/endpoint-protection-pip-combined-ca.pem"
expect_env REQUESTS_CA_BUNDLE            "$RUN_DIR/endpoint-protection-pip-combined-ca.pem"
expect_env POETRY_CERTIFICATES_PYPI_CERT "$RUN_DIR/endpoint-protection-pip-combined-ca.pem"
# uv >= 0.11.0 uses UV_SYSTEM_CERTS; older installs use UV_NATIVE_TLS instead
if [ -n "${UV_SYSTEM_CERTS:-}" ]; then
  expect_bool UV_SYSTEM_CERTS
else
  expect_bool UV_NATIVE_TLS
fi

# Ruby
expect_env BUNDLE_SSL_CA_CERT "$RUN_DIR/endpoint-protection-ruby-combined-ca.pem"
check_gemrc

# curl
expect_env CURL_CA_BUNDLE "$RUN_DIR/endpoint-protection-openssl-combined-ca.pem"

# Maven — check for Aikido proxy block in ~/.m2/settings.xml (written unconditionally)
if [ -f "$HOME/.m2/settings.xml" ] && grep -q "<!-- aikido-safe-chain-start -->" "$HOME/.m2/settings.xml"; then
  ok "~/.m2/settings.xml"
else
  fail "~/.m2/settings.xml" "Aikido proxy block not found"
fi

# Git (gitconfig, not an env var)
git_ca=$(git config --global http.sslCAInfo 2>/dev/null || true)
[ "$git_ca" = "$RUN_DIR/endpoint-protection-openssl-combined-ca.pem" ] \
  && ok "git http.sslCAInfo" \
  || fail "git http.sslCAInfo" "expected '$RUN_DIR/endpoint-protection-openssl-combined-ca.pem', got '${git_ca:-<not set>}'"

echo
echo "MDM configuration profiles"

if profiles_out=$(sudo /usr/bin/profiles show -type configuration 2>/dev/null); then
  grep -q "Add Aikido Endpoint to System Extensions"               <<< "$profiles_out" \
    && ok "System extension approved" \
    || fail "System extension approved" "profile not found"
  grep -q "com.aikidosecurity.endpointprotection.servicemanagement" <<< "$profiles_out" \
    && ok "Process locking" \
    || fail "Process locking" "profile not found"
  grep -q "Aikido Endpoint Content Filter Profile"                 <<< "$profiles_out" \
    && ok "Content filter" \
    || fail "Content filter" "profile not found"
  grep -q "Aikido Root CA (Trust)"                                 <<< "$profiles_out" \
    && ok "Root CA trust" \
    || fail "Root CA trust" "profile not found"
else
  echo "  [SKIP] Could not read MDM profiles -- re-run with sudo"
fi

exit "$status"
