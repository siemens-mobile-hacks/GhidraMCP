#!/usr/bin/env bash
# Builds the e2e test binaries, (re)creates the e2e Ghidra project and runs the
# GhidraMCP server headless on it (blocks until shutdown_ghidra is called).
#   tests/e2e/headless.sh [port]        default port 18080
# Requires the extension to be installed (./install.sh).
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PORT="${1:-18080}"
E2E="${ROOT}/e2e-work"
BIN="${E2E}/bin"
PROJ="${E2E}/project"
mkdir -p "${BIN}" "${PROJ}"

gcc -O1 -g0 -fno-pie -no-pie -o "${BIN}/mcp_target" "${ROOT}/tests/e2e/target.c"
if command -v arm-none-eabi-gcc >/dev/null; then
    arm-none-eabi-gcc -mthumb -mcpu=cortex-m3 -O1 -c -o "${BIN}/thumb.o" "${ROOT}/tests/e2e/target.c"
fi

if [[ ! -d "${PROJ}/MCPTest.rep" || "${E2E_REIMPORT:-0}" == 1 ]]; then
    rm -rf "${PROJ}/MCPTest.rep" "${PROJ}/MCPTest.gpr"
    "${GHIDRA_HOME}/support/analyzeHeadless" "${PROJ}" MCPTest -import "${BIN}/mcp_target" \
        ${BIN}/thumb.o 2>&1 | grep -E "REPORT|ERROR" || true
fi

exec "${GHIDRA_HOME}/support/analyzeHeadless" "${PROJ}" MCPTest -process mcp_target -readOnly \
    -noanalysis -postScript StartGhidraMcpServer.java "${PORT}"
