#!/usr/bin/env bash
# Build the React UI and stage the output into internal/api/static/ so the
# engine binary embeds it via go:embed. Run from the engine/ directory.
#
# Vite is already configured (ui/vite.config.ts) to write its build output
# directly into engine/internal/api/static/, so this script just kicks off the
# npm build and restores the .gitkeep sentinel afterwards so the empty-tree
# case keeps compiling on a fresh clone.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_DIR="$(cd "${SCRIPT_DIR}/../ui" && pwd)"
STATIC_DIR="${SCRIPT_DIR}/internal/api/static"

echo "building UI in ${UI_DIR}"
npm --prefix "${UI_DIR}" run build

touch "${STATIC_DIR}/.gitkeep"

echo "staged build into ${STATIC_DIR}"
