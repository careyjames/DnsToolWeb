#!/bin/bash
# Git Health Check — run at session start AND before every push
# Fixes: stale lock files, interrupted rebases, detached HEAD
# Safe to run repeatedly — only fixes problems, never destructive
#
# HISTORY: Stale lock files have caused PUSH_REJECTED errors, stalled rebases,
# and wasted nearly a full day of production (Feb 2026). This script exists
# because lock files are PRODUCTION FAILURES, not cosmetic issues.

set -e
cd /home/runner/workspace 2>/dev/null || exit 0

FIXED=0

# 1. Remove ALL stale lock files — comprehensive sweep
#    Uses find to catch EVERY .lock file in .git, including deep nested paths
#    like gitsafe-backup, packed-refs, remotes, objects, etc.
LOCK_COUNT=0
while IFS= read -r lockfile; do
  if [ -n "$lockfile" ]; then
    rm -f "$lockfile" 2>/dev/null && echo "Removed stale $lockfile" && LOCK_COUNT=$((LOCK_COUNT+1))
  fi
done < <(find .git -name "*.lock" -type f 2>/dev/null)

if [ "$LOCK_COUNT" -gt 0 ]; then
  FIXED=$((FIXED+LOCK_COUNT))
  echo "Cleared $LOCK_COUNT lock file(s)"
fi

# 2. Abort interrupted rebase
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  git rebase --abort 2>/dev/null && echo "Aborted interrupted rebase" && FIXED=$((FIXED+1))
  rm -rf .git/rebase-merge .git/rebase-apply 2>/dev/null
fi

# 3. Fix detached HEAD — reattach to main
CURRENT_HEAD=$(cat .git/HEAD 2>/dev/null)
if echo "$CURRENT_HEAD" | grep -qv "ref:"; then
  printf 'ref: refs/heads/main\n' > .git/HEAD 2>/dev/null && echo "Reattached HEAD to main" && FIXED=$((FIXED+1))
fi

# 4. Report status
if [ $FIXED -eq 0 ]; then
  echo "Git health: CLEAN — zero lock files, no interrupted operations"
else
  echo "Git health: fixed $FIXED issue(s)"
fi

git branch --show-current 2>/dev/null || true
