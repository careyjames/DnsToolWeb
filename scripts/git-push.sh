#!/bin/bash
# Direct push to GitHub via PAT — bypasses Replit Git panel and lock files
# Usage: bash scripts/git-push.sh

set -e
cd /home/runner/workspace

REPO="careyjames/DnsToolWeb"
BRANCH="main"
PAT_URL="https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git"

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
git push "${PAT_URL}" ${BRANCH}

echo "Updating local remote tracking..."
bash scripts/git-health-check.sh 2>/dev/null || true
git fetch "${PAT_URL}" ${BRANCH} 2>/dev/null || true

echo "Push complete. Verifying sync..."
REMAINING=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
if [ "$REMAINING" = "0" ]; then
  echo "Fully synced — Git panel should show up-to-date."
else
  echo "Warning: Git panel may still show ${REMAINING} unpushed. Run 'bash scripts/git-health-check.sh' then 'git fetch' in Shell to fix."
fi
