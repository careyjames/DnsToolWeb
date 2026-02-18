#!/bin/bash
# Git Panel Reset — fixes the Replit Git panel showing stale commit counts
# Run from the Shell tab: bash scripts/git-panel-reset.sh
#
# WHY: The agent's push script uses git ls-remote (read-only) for sync
# verification, but the Git panel reads origin/main (the tracking ref).
# A stale .lock file can block the tracking ref from updating, causing
# the panel to show "X commits ahead" even though GitHub is current.

cd /home/runner/workspace

echo "=== Git Panel Reset ==="
echo ""

FIXED=0

if [ -f ".git/refs/remotes/origin/main.lock" ]; then
  rm -f ".git/refs/remotes/origin/main.lock" 2>/dev/null
  echo "  Removed stale refs/remotes/origin/main.lock"
  FIXED=$((FIXED+1))
else
  echo "  No remote ref lock found (good)"
fi

if [ -f ".git/objects/maintenance.lock" ]; then
  rm -f ".git/objects/maintenance.lock" 2>/dev/null
  echo "  Removed maintenance.lock"
  FIXED=$((FIXED+1))
else
  echo "  No maintenance lock found (good)"
fi

echo ""
echo "Fetching latest from GitHub..."
if git fetch 2>/dev/null; then
  echo "  Fetch successful — tracking refs updated"
else
  echo "  Fetch failed — trying with PAT..."
  if [ -n "$CAREY_PAT_ALL3_REPOS" ]; then
    git fetch "https://${CAREY_PAT_ALL3_REPOS}@github.com/careyjames/DnsToolWeb.git" main:refs/remotes/origin/main 2>/dev/null
    echo "  PAT fetch complete"
  else
    echo "  No PAT available. Try: git fetch"
  fi
fi

echo ""
LOCAL=$(git rev-parse HEAD 2>/dev/null)
REMOTE=$(git rev-parse origin/main 2>/dev/null)
AHEAD=$(git rev-list origin/main..HEAD --count 2>/dev/null || echo "?")

echo "  Local HEAD:  $LOCAL"
echo "  origin/main: $REMOTE"
echo "  Commits ahead: $AHEAD"
echo ""

if [ "$AHEAD" = "0" ]; then
  echo "GIT PANEL: Should now show 0 ahead, 0 behind."
  echo "Close and re-open the Git tab to refresh."
else
  echo "GIT PANEL: Shows $AHEAD commit(s) ahead."
  echo "These are local checkpoints not yet pushed to GitHub."
  echo "Run 'bash scripts/git-push.sh' to push them."
fi
echo ""
echo "Done. $FIXED lock file(s) cleared."
