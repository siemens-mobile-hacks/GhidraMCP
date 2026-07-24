#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
GHIDRA_DIR="${GHIDRA_HOME}/Ghidra"
LIB_DIR="${ROOT_DIR}/lib"
APPLICATION_PROPERTIES="${GHIDRA_DIR}/application.properties"

if [[ ! -f "${APPLICATION_PROPERTIES}" ]]; then
    echo "Ghidra not found: ${APPLICATION_PROPERTIES}" >&2
    echo "Set GHIDRA_HOME to the Ghidra installation directory." >&2
    exit 1
fi

GHIDRA_VERSION="$(sed -n 's/^application\.version=//p' "${APPLICATION_PROPERTIES}")"
if [[ -z "${GHIDRA_VERSION}" ]]; then
    echo "Unable to determine the Ghidra version from ${APPLICATION_PROPERTIES}" >&2
    exit 1
fi

copy_jar() {
    local source="$1"
    local destination="$2"

    if [[ ! -f "${source}" ]]; then
        echo "Required Ghidra library not found: ${source}" >&2
        exit 1
    fi

    cp -- "${source}" "${LIB_DIR}/${destination}"
}

mkdir -p -- "${LIB_DIR}"

copy_jar "${GHIDRA_DIR}/Features/Base/lib/Base.jar" Base.jar
copy_jar "${GHIDRA_DIR}/Features/Decompiler/lib/Decompiler.jar" Decompiler.jar
copy_jar "${GHIDRA_DIR}/Framework/DB/lib/DB.jar" DB.jar
copy_jar "${GHIDRA_DIR}/Framework/Docking/lib/Docking.jar" Docking.jar
copy_jar "${GHIDRA_DIR}/Framework/FileSystem/lib/FileSystem.jar" FileSystem.jar
copy_jar "${GHIDRA_DIR}/Framework/Generic/lib/Generic.jar" Generic.jar
copy_jar "${GHIDRA_DIR}/Framework/Generic/lib/commons-lang3-3.20.0.jar" commons-lang3.jar
copy_jar "${GHIDRA_DIR}/Framework/Generic/lib/log4j-api-2.25.4.jar" log4j-api.jar
copy_jar "${GHIDRA_DIR}/Framework/Generic/lib/log4j-core-2.25.4.jar" log4j-core.jar
copy_jar "${GHIDRA_DIR}/Framework/Graph/lib/Graph.jar" Graph.jar
copy_jar "${GHIDRA_DIR}/Framework/Help/lib/javahelp-2.0.05.jar" javahelp.jar
copy_jar "${GHIDRA_DIR}/Framework/Project/lib/Project.jar" Project.jar
copy_jar "${GHIDRA_DIR}/Framework/SoftwareModeling/lib/SoftwareModeling.jar" SoftwareModeling.jar
copy_jar "${GHIDRA_DIR}/Framework/Utility/lib/Utility.jar" Utility.jar
copy_jar "${GHIDRA_DIR}/Framework/Gui/lib/Gui.jar" Gui.jar

GSON_JAR="$(find "${GHIDRA_DIR}/Framework/Generic/lib" -maxdepth 1 -type f -name 'gson-*.jar' -print -quit)"
if [[ -z "${GSON_JAR}" ]]; then
    echo "Required Gson library not found in ${GHIDRA_DIR}/Framework/Generic/lib" >&2
    exit 1
fi
copy_jar "${GSON_JAR}" gson.jar

echo "Building GhidraMCP for Ghidra ${GHIDRA_VERSION} from ${GHIDRA_HOME}"
mvn -f "${ROOT_DIR}/pom.xml" clean package "$@"

echo "Extension package: ${ROOT_DIR}/target/GhidraMCP-1.0-SNAPSHOT.zip"
