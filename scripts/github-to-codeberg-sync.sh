#!/bin/bash
# Sync GitHub repos to Codeberg mirrors
# Usage: ./scripts/github-to-codeberg-sync.sh
# Requires: CODEBERG_FORGEJO_API env var, git with GitHub credentials

set -euo pipefail

CODEBERG_TOKEN="${CODEBERG_FORGEJO_API:?Set CODEBERG_FORGEJO_API}"
WORK=$(mktemp -d)
trap "rm -rf $WORK" EXIT

sync_repo() {
  local gh_repo="$1"
  local cb_repo="$2"
  echo "Syncing github.com/careyjames/${gh_repo} → codeberg.org/careybalboa/${cb_repo}..."

  if ! git clone --bare "https://github.com/careyjames/${gh_repo}.git" "${WORK}/${cb_repo}"; then
    echo "  ✗ Failed to clone ${gh_repo}" >&2
    return 1
  fi

  if ! git -C "${WORK}/${cb_repo}" push --mirror \
    "https://careybalboa:${CODEBERG_TOKEN}@codeberg.org/careybalboa/${cb_repo}.git"; then
    echo "  ✗ Failed to push ${cb_repo}" >&2
    return 1
  fi

  echo "  ✓ ${cb_repo} synced"
}

sync_repo "dns-tool-web" "dns-tool-web"
sync_repo "dns-tool-cli" "dns-tool-cli"

echo ""
echo "Public repos synced. For dns-tool-intel (private), run:"
echo "  git clone --bare https://github.com/careyjames/dns-tool-intel.git /tmp/intel-sync"
echo "  git -C /tmp/intel-sync push --mirror https://careybalboa:\${CODEBERG_FORGEJO_API}@codeberg.org/careybalboa/dns-tool-intel.git"
