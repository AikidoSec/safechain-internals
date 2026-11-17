#!/usr/bin/env bash
# Installs and starts Aikido Device Protection on a GitHub Actions Linux job,
# then hands the agent's proxy and CA-trust variables to every later step.
#
# Inputs (environment):
#   AIKIDO_TOKEN          enrollment token (required)
#   AIKIDO_SELF_CHECK     "true" fails the step unless a known test package is
#                         blocked through the exported settings (default: off)
#   GITHUB_ENV            set by Actions; later steps read the variables
#                         written here. Point it at a temp file to test locally.
#
# Uses the installer from safe-chain main, as the help page does. That
# installer pins the agent release and checks each package's SHA-256, and a
# bot bumps it on every release, so this action always installs the latest
# agent. The URL is fixed here, not configurable. Inputs the installer reads
# from the environment (AIKIDO_PACKAGE_FILE) reach it as they would when the
# installer is run by hand.

set -euo pipefail

readonly INSTALLER_URL="https://raw.githubusercontent.com/AikidoSec/safe-chain/main/install-scripts/install-endpoint-linux.sh"
START=/usr/bin/aikido-endpoint-protection-start
LOG_DIR=/var/log/aikidosecurity/endpoint-protection
TEST_URL="https://registry.npmjs.org/safe-chain-test/-/safe-chain-test-0.0.1-security.tgz"

in_actions() {
    [ "${GITHUB_ACTIONS:-}" = "true" ]
}

group() {
    if in_actions; then
        echo "::group::$1"
    else
        echo "== $1"
    fi
}

endgroup() {
    if in_actions; then
        echo "::endgroup::"
    fi
}

fail() {
    if in_actions; then
        echo "::error title=Aikido Device Protection::$1"
    else
        echo "Error: $1" >&2
    fi
    exit 1
}

# The runner is gone after the job, so its log files can't be read later:
# print the end of the agent's logs into the job log before failing.
show_agent_logs() {
    endgroup
    group "Agent logs (last 100 lines)"
    for f in "$LOG_DIR/endpoint-protection.log" "$LOG_DIR/endpoint-protection.err"; do
        echo "--- $f"
        as_root tail -n 100 "$f" 2>/dev/null || echo "(not readable)"
    done
    endgroup
}

[ "$(uname -s)" = "Linux" ] || fail "Only Linux runners are supported (this job runs on $(uname -s))."

if [ -z "${AIKIDO_TOKEN:-}" ]; then
    fail "No token. Pass it with 'token: \${{ secrets.AIKIDO_TOKEN }}'. Pull requests from forks and Dependabot get no repository secrets, so this step fails there instead of running unprotected."
fi
if in_actions; then echo "::add-mask::$AIKIDO_TOKEN"; fi

[ -n "${GITHUB_ENV:-}" ] || fail "GITHUB_ENV is not set. Outside Actions, set it to a temp file: GITHUB_ENV=\$(mktemp) $0"

# Job containers run as root without sudo; hosted runners need sudo.
if [ "$(id -u)" -eq 0 ]; then
    as_root() { "$@"; }
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    # The installer's own inputs, as it forwards them when it escalates itself.
    # --preserve-env keeps the token out of the process list (sudo VAR=x would put it in argv).
    as_root() { sudo -n --preserve-env=AIKIDO_TOKEN,AIKIDO_PACKAGE_FILE "$@"; }
else
    fail "Needs root: run as root or with passwordless sudo."
fi

command -v curl >/dev/null 2>&1 || fail "curl is required. Install it before this step (e.g. apt-get install -y curl in a job container)."

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

group "Install Aikido Device Protection"
curl -fsSL --retry 3 -o "$tmp/install.sh" "$INSTALLER_URL" || fail "Could not download the installer from $INSTALLER_URL"
export AIKIDO_TOKEN
# Already root here, so the installer skips its own sudo/doas escalation
as_root sh "$tmp/install.sh" --container ||
    fail "The installer failed (exit $?). Its output is in the 'Install Aikido Device Protection' group above."
endgroup

group "Start Aikido Device Protection"
# With systemd running (hosted runners) the package already started the unit
# and this only waits; in a job container it starts the daemon.
as_root "$START" --wait-for-healthy || {
    rc=$?
    show_agent_logs
    fail "The agent did not start or never became healthy (exit $rc). The end of its logs is in the 'Agent logs' group above."
}

# Healthy can pass through the proxy.addr.txt fallback before setup has written
# /etc/profile.d/aikido-proxy.sh, so exporting now would miss the proxy
# variables. The daemon saves setup_completed once setup ran and it is
# protected; wait for that and the proxy drop-in.
config=/var/lib/aikidosecurity/endpoint-protection/run/config.json
for _ in $(seq 1 60); do
    if [ -f /etc/profile.d/aikido-proxy.sh ] &&
        as_root grep -Eq '"setup_completed"[[:space:]]*:[[:space:]]*true' "$config" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [ "${ready:-}" != 1 ]; then
    show_agent_logs
    fail "The agent started but did not finish setup within 60s. The end of its logs is in the 'Agent logs' group above."
fi
echo "Setup complete."
endgroup

group "Export settings to later steps"
# Steps run 'bash --noprofile --norc', so /etc/profile.d never reaches them.
# Source the agent's drop-ins in a clean shell and export whatever they set,
# rather than hardcoding names that change as tools are added.
shopt -s nullglob
dropins=(/etc/profile.d/aikido-*.sh)
shopt -u nullglob
[ "${#dropins[@]}" -gt 0 ] || fail "The agent wrote no /etc/profile.d/aikido-*.sh files; nothing to export."

dump_env() {
    # NUL-separated so values with newlines survive. Exits non-zero if a
    # drop-in can't be read or fails to load.
    env -i PATH="$PATH" bash --noprofile --norc -c '
        for f in "$@"; do
            . "$f" || { echo "failed to load $f" >&2; exit 1; }
        done
        unset _ PWD SHLVL OLDPWD
        env -0' bash "$@"
}

# Capture both environments before writing anything, so a drop-in that fails
# fails the step instead of leaving later steps with part of the settings.
dump_env >"$tmp/env.before" || fail "Could not start a clean shell to read the agent's settings."
dump_env "${dropins[@]}" >"$tmp/env.after" ||
    fail "Could not load the agent's settings from ${dropins[*]}."

declare -A before=()
while IFS= read -r -d '' kv; do before["${kv%%=*}"]="${kv#*=}"; done <"$tmp/env.before"

exported=0
while IFS= read -r -d '' kv; do
    name="${kv%%=*}" value="${kv#*=}"
    if [ "${before[$name]+set}" = set ] && [ "${before[$name]}" = "$value" ]; then continue; fi
    delim="AIKIDO_EOF_$RANDOM$RANDOM"
    printf '%s<<%s\n%s\n%s\n' "$name" "$delim" "$value" "$delim" >>"$GITHUB_ENV"
    echo "$name=$value"
    export "$name=$value"
    exported=$((exported + 1))
done <"$tmp/env.after"
[ "$exported" -gt 0 ] || fail "The drop-ins (${dropins[*]}) set no variables."
endgroup

if [ "${AIKIDO_SELF_CHECK:-false}" = "true" ]; then
    group "Self-check"
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "$TEST_URL" || true)
    case "$code" in
        403) echo "Blocked the test package (HTTP 403): later steps are protected." ;;
        200) fail "The test package downloaded (HTTP 200): traffic is not going through the agent." ;;
        *) fail "Self-check got HTTP '${code:-none}' for $TEST_URL; expected 403." ;;
    esac
    endgroup
fi
