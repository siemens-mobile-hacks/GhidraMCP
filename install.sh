#!/usr/bin/env bash
# Installs the built GhidraMCP extension into the user's Ghidra settings
# directory (the same place "File -> Install Extensions" uses).
# Restart Ghidra afterwards. Usage: ./install.sh [path/to/GhidraMCP-*.zip]

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PROPS="${GHIDRA_HOME}/Ghidra/application.properties"
ZIP="${1:-${ROOT_DIR}/target/GhidraMCP-1.0-SNAPSHOT.zip}"

[[ -f "${PROPS}" ]] || { echo "Ghidra not found: ${PROPS} (set GHIDRA_HOME)" >&2; exit 1; }
[[ -f "${ZIP}" ]] || { echo "Extension zip not found: ${ZIP} (run ./build.sh)" >&2; exit 1; }

VERSION="$(sed -n 's/^application\.version=//p' "${PROPS}")"
RELEASE="$(sed -n 's/^application\.release\.name=//p' "${PROPS}")"
SETTINGS="${XDG_CONFIG_HOME:-${HOME}/.config}/ghidra/ghidra_${VERSION}_${RELEASE}"
EXT_DIR="${SETTINGS}/Extensions"

mkdir -p -- "${EXT_DIR}"
if [[ -d "${EXT_DIR}/GhidraMCP" ]]; then
    BACKUP_DIR="${SETTINGS}/ExtensionBackups"
    mkdir -p -- "${BACKUP_DIR}"
    BACKUP="${BACKUP_DIR}/GhidraMCP-$(date +%Y%m%d-%H%M%S)"
    mv -- "${EXT_DIR}/GhidraMCP" "${BACKUP}"
    echo "Previous version moved to ${BACKUP}"
    # Keep only the three most recent GhidraMCP backups.
    ls -1d "${BACKUP_DIR}"/GhidraMCP-* 2>/dev/null | sort | head -n -3 | while read -r old; do
        rm -rf -- "${old}"
    done
fi
unzip -q -- "${ZIP}" -d "${EXT_DIR}"
echo "Installed GhidraMCP into ${EXT_DIR}/GhidraMCP (Ghidra ${VERSION} ${RELEASE}). Restart Ghidra."
