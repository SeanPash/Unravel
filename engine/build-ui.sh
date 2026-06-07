#!/usr/bin/env bash
# Build the React UI and stage the output into internal/api/static/ so the
# engine binary embeds it via go:embed. Run from the engine/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$(cd "${SCRIPT_DIR}/../ui" && pwd)"
STATIC_DIR="${SCRIPT_DIR}/internal/api/static"

echo "building UI in ${UI_DIR}"
npm --prefix "${UI_DIR}" run build

echo "staging ${UI_DIR}/dist -> ${STATIC_DIR}"
find "${STATIC_DIR}" -mindepth 1 ! -name '.gitkeep' -delete
cp -R "${UI_DIR}/dist/." "${STATIC_DIR}/"

echo "done"
