#!/usr/bin/env bash
# Dev loop: stop the headless e2e server (via the shutdown_ghidra MCP tool),
# rebuild, reinstall and start it again. Waits until the server answers.
#   tests/e2e/cycle.sh [port]
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${1:-18080}"
URL="http://127.0.0.1:${PORT}/mcp"
export TMPDIR="${TMPDIR:-/tmp/codex}"
mkdir -p "${TMPDIR}" "${ROOT}/e2e-work"

call() {
    curl -s -m 30 -H 'Content-Type: application/json' "${URL}" -d "$1" || true
}

if curl -s -m 2 -o /dev/null "${URL}" -d '{}'; then
    call '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"shutdown_ghidra","arguments":{"force":true}}}'
    echo
    for _ in $(seq 1 60); do
        curl -s -m 1 -o /dev/null "${URL}" -d '{}' || break
        sleep 1
    done
fi

"${ROOT}/build.sh" -q
"${ROOT}/install.sh"

setsid "${ROOT}/tests/e2e/headless.sh" "${PORT}" > "${ROOT}/e2e-work/headless.log" 2>&1 < /dev/null &
for _ in $(seq 1 180); do
    if curl -s -m 1 -o /dev/null "${URL}" -d '{}'; then
        echo "server up on ${URL}"
        exit 0
    fi
    if grep -qE "ERROR .*Abort|Exception in thread" "${ROOT}/e2e-work/headless.log"; then
        break
    fi
    sleep 1
done
echo "server failed to start; see e2e-work/headless.log" >&2
tail -20 "${ROOT}/e2e-work/headless.log" >&2
exit 1
