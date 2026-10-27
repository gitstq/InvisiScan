#!/usr/bin/env bash
# Publish InvisiScan to a GitHub repository.
#
# ⚠️  READ THIS FIRST
# The GitHub token that arrived with this project's build instructions was
# stored in PLAIN TEXT inside a publicly shareable "file courier" link that had
# already been fetched 16 times before this repository was written. Anybody who
# opened that link holds a token with full `repo` scope over every repository
# of the account -- including `delete_repo`.
#
# That token should be REVOKED, not reused:
#   https://github.com/settings/tokens
#
# This script deliberately uses whatever credentials you have already configured
# (`gh auth login`, or an SSH key) instead of an inline token, so nothing
# sensitive ends up in the repository history.
#
# Usage:
#   ./scripts/publish.sh <owner>/<repo>        # repo must already exist
#   ./scripts/publish.sh --create <repo>       # create it via the gh CLI first

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ $# -eq 0 ]]; then
  echo "usage: $0 <owner>/<repo> | $0 --create <repo>" >&2
  exit 2
fi

if [[ "$1" == "--create" ]]; then
  NAME="${2:?repository name required}"
  echo "==> creating public repository $NAME"
  gh repo create "$NAME" --public \
    --description "🔍 Zero-dependency Unicode safety scanner: invisible characters, Trojan Source bidi controls and homograph identifiers." \
    --homepage "https://github.com/$NAME#readme"
  OWNER="$(gh api user --jq .login)"
  TARGET="$OWNER/$NAME"
else
  TARGET="$1"
fi

# Verify everything is green before anything leaves the machine.
echo "==> verifying before publishing"
python3 -m pytest -q
python3 -m invisiscan invisiscan scripts .github

BRANCH="$(git branch --show-current 2>/dev/null || echo main)"

if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "https://github.com/${TARGET}.git"
else
  git remote add origin "https://github.com/${TARGET}.git"
fi

echo "==> pushing $BRANCH -> https://github.com/${TARGET}"
git push -u origin "$BRANCH"

echo
echo "==> done"
echo "    repository: https://github.com/${TARGET}"
echo "    actions:    https://github.com/${TARGET}/actions"
echo "    security:   https://github.com/${TARGET}/security/code-scanning"
echo
echo "Note: this project ships as a library/CLI, so no Release binary is published."
echo "Publish to PyPI instead with:  python -m twine upload dist/*"
