#!/bin/bash
# Direct push to GitHub via PAT — bypasses Replit Git panel and lock files
# Usage: bash scripts/git-push.sh

set -e
cd /home/runner/workspace

REPO="careyjames/DnsToolWeb"
BRANCH="main"

if [ -z "$CAREY_PAT_ALL3_REPOS" ]; then
  echo "Error: CAREY_PAT_ALL3_REPOS secret not set"
  exit 1
fi

AHEAD=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
echo "Commits ahead of origin/${BRANCH}: ${AHEAD}"

if [ "$AHEAD" = "0" ]; then
  echo "Nothing to push."
  exit 0
fi

git log --oneline origin/${BRANCH}..HEAD

echo ""
echo "Pushing to github.com/${REPO} ${BRANCH}..."
git push "https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git" ${BRANCH}
echo "Push complete."
