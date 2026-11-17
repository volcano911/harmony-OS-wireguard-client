#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TOOLS_HOME="${HARMONYOS_COMMANDLINE_HOME:-}"
if [[ -z "${TOOLS_HOME}" ]]; then
  echo "Set HARMONYOS_COMMANDLINE_HOME to the HarmonyOS command-line-tools directory." >&2
  exit 1
fi

HVIGORW="${TOOLS_HOME}/bin/hvigorw"
SDK_ROOT="${TOOLS_HOME}/sdk"
BUILD_MODE="${BUILD_MODE:-debug}"

if [[ ! -x "${HVIGORW}" ]]; then
  echo "HarmonyOS Hvigor not found: ${HVIGORW}" >&2
  exit 1
fi

if [[ ! -f "${SDK_ROOT}/default/sdk-pkg.json" ]]; then
  echo "HarmonyOS SDK metadata not found: ${SDK_ROOT}/default/sdk-pkg.json" >&2
  exit 1
fi

cd "${PROJECT_ROOT}"

if [[ ! -f build-profile.json5 ]]; then
  cp build-profile.template.json5 build-profile.json5
fi

if [[ ! -f entry/build-profile.json5 ]]; then
  cp entry/build-profile.template.json5 entry/build-profile.json5
fi

export PATH="${TOOLS_HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export DEVECO_SDK_HOME="${SDK_ROOT}"

"${HVIGORW}" clean assembleHap \
  --mode module \
  -p product=default \
  -p module=entry@default \
  -p "buildMode=${BUILD_MODE}" \
  --no-daemon \
  --no-parallel \
  --no-incremental

SOURCE_HAP="entry/build/default/outputs/default/entry-default-unsigned.hap"
APP_VERSION="$(sed -n 's/.*"versionName"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' AppScope/app.json5 | head -n 1)"
APP_VERSION="${APP_VERSION:-0.0.0}"
OUTPUT_NAME="harmonyos-wg-client-${APP_VERSION}-api23-arm64-${BUILD_MODE}-unsigned.hap"

if [[ ! -f "${SOURCE_HAP}" ]]; then
  echo "Expected unsigned HAP not found: ${SOURCE_HAP}" >&2
  exit 1
fi

unzip -tq "${SOURCE_HAP}" >/dev/null

HAP_LISTING="$(unzip -l "${SOURCE_HAP}")"
if ! grep -q "libs/arm64-v8a/libwg_tunnel.so" <<< "${HAP_LISTING}"; then
  echo "Native library missing from HAP: libs/arm64-v8a/libwg_tunnel.so" >&2
  exit 1
fi
if grep -q "libudp_socket.so" <<< "${HAP_LISTING}"; then
  echo "Stale relay library found in HAP: libudp_socket.so" >&2
  exit 1
fi

mkdir -p dist
cp "${SOURCE_HAP}" "dist/${OUTPUT_NAME}"
(
  cd dist
  sha256sum "${OUTPUT_NAME}" > SHA256SUMS.txt
)

echo "Unsigned HAP: ${PROJECT_ROOT}/dist/${OUTPUT_NAME}"
echo "Checksum: ${PROJECT_ROOT}/dist/SHA256SUMS.txt"
echo "This package has no Huawei developer signature and cannot be installed on a retail HarmonyOS phone."
