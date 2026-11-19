#!/usr/bin/env zsh
set -euo pipefail

# Ensure script runs from the repository root
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_DIR="${SCRIPT_DIR}/build"
INSTALL_PREFIX="${BUILD_DIR}/install"
APP_NAME="KeePassXC.app"
DEST_APP="/Applications/${APP_NAME}"

echo "==> Configuring Release build in ${BUILD_DIR}..."
cmake -B "${BUILD_DIR}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="$(uname -m)" \
  -DWITH_XC_ALL=ON \
  -DWITH_TESTS=OFF

echo "==> Compiling KeePassXC..."
cmake --build "${BUILD_DIR}" --parallel

echo "==> Staging standalone app bundle via cmake --install..."
rm -rf "${INSTALL_PREFIX}"
cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"

STAGED_APP="${INSTALL_PREFIX}/${APP_NAME}"

if [[ ! -d "${STAGED_APP}" ]]; then
  echo "Error: Staged application not found at ${STAGED_APP}" >&2
  exit 1
fi

echo "==> Ad-hoc code signing ${APP_NAME} with Hardened Runtime..."
ENTITLEMENTS_FILE="${SCRIPT_DIR}/share/macosx/keepassxc-adhoc.entitlements"
codesign --force --deep --options=runtime --entitlements "${ENTITLEMENTS_FILE}" --sign - "${STAGED_APP}"

echo "==> Closing running KeePassXC instances if any..."
osascript -e 'quit app "KeePassXC"' 2>/dev/null || true
for i in {1..10}; do
  if ! pgrep -x "KeePassXC" >/dev/null; then
    break
  fi
  sleep 0.5
done
killall KeePassXC 2>/dev/null || true

echo "==> Installing to ${DEST_APP}..."
rm -rf "${DEST_APP}"
cp -R "${STAGED_APP}" /Applications/

echo "==> Successfully installed ${APP_NAME} to /Applications!"
