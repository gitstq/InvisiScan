#!/usr/bin/env bash
# Build InvisiScan distributables.
#   ./scripts/build.sh            wheel + sdist
#   ./scripts/build.sh bundle     also produce a standalone .pyz (needs python3 only)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
MODE="${1:-dist}"

echo "==> InvisiScan build (python: $($PYTHON --version 2>&1))"

# Nothing to install from pip at runtime; only the build backend is needed.
"$PYTHON" -c "import build" 2>/dev/null || "$PYTHON" -m pip install --quiet --upgrade build wheel setuptools

rm -rf dist build ./*.egg-info

echo "==> building wheel + sdist"
"$PYTHON" -m build

if [ "$MODE" = "bundle" ]; then
  echo "==> building standalone zipapp"
  rm -rf .builddeps
  "$PYTHON" -m pip install --quiet --target .builddeps .
  "$PYTHON" -m zipapp .builddeps \
    -m "invisiscan.cli:main" \
    -p "/usr/bin/env python3" \
    -o dist/invisiscan.pyz
  rm -rf .builddeps
  chmod +x dist/invisiscan.pyz
  echo "    dist/invisiscan.pyz  (run with: python3 dist/invisiscan.pyz --help)"
fi

echo "==> verifying wheel installs and runs"
"$PYTHON" -m pip install --quiet --force-reinstall dist/*.whl
invisiscan --version
"$PYTHON" -m invisiscan --help > /dev/null
echo "    CLI smoke test passed"

echo
echo "==> artifacts"
ls -la dist/
