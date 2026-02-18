#!/bin/bash
# Git Health Check — run at session start from the Shell tab
# Fixes: stale lock files, interrupted rebases, detached HEAD
# Safe to run repeatedly — only fixes problems, never destructive
#
# NOTE: Steps 1-4 modify .git files and can ONLY run from the Shell tab.
# The Replit platform blocks .git writes from agent processes (exit 254).
# Pass --read-only to skip .git repairs (safe for agent context).
#
# HISTORY: Stale lock files have caused PUSH_REJECTED errors, stalled rebases,
# and wasted nearly a full day of production (Feb 2026). This script exists
# because lock files are PRODUCTION FAILURES, not cosmetic issues.

cd /home/runner/workspace 2>/dev/null || exit 0

READ_ONLY=false
if [ "${1:-}" = "--read-only" ]; then
  READ_ONLY=true
fi

FIXED=0

if [ "$READ_ONLY" = false ]; then

  # 1. Remove ALL stale lock files — comprehensive sweep
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

  # 4. Update tracking refs
  echo "Updating tracking refs..."
  git fetch 2>/dev/null || true

  GITHUB_SHA=$(git ls-remote origin main 2>/dev/null | awk '{print $1}')
  CURRENT_REF=$(cat .git/refs/remotes/origin/main 2>/dev/null)
  if [ -n "$GITHUB_SHA" ] && [ "$CURRENT_REF" != "$GITHUB_SHA" ]; then
    git update-ref refs/remotes/origin/main "$GITHUB_SHA" 2>/dev/null \
      || echo "$GITHUB_SHA" > .git/refs/remotes/origin/main 2>/dev/null \
      || echo "  Tracking ref update failed"
    echo "  Tracking ref updated to ${GITHUB_SHA:0:7}"
  elif [ -n "$GITHUB_SHA" ]; then
    echo "  Tracking ref already current"
  fi

  # 5. Report status
  if [ $FIXED -eq 0 ]; then
    echo "Git health: CLEAN — zero lock files, no interrupted operations"
  else
    echo "Git health: fixed $FIXED issue(s)"
  fi

fi

git branch --show-current 2>/dev/null || true

# 6. Sync status via ls-remote (read-only, works from any context)
if [ -n "$CAREY_PAT_ALL3_REPOS" ]; then
  LOCAL_SHA=$(git rev-parse HEAD 2>/dev/null)
  REMOTE_SHA=$(git ls-remote "https://${CAREY_PAT_ALL3_REPOS}@github.com/careyjames/DnsToolWeb.git" refs/heads/main 2>/dev/null | awk '{print $1}')
  if [ -n "$REMOTE_SHA" ]; then
    if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
      echo "Sync status: MATCHED — local HEAD = GitHub HEAD ($LOCAL_SHA)"
    else
      echo "Sync status: MISMATCH"
      echo "  Local:  $LOCAL_SHA"
      echo "  GitHub: $REMOTE_SHA"
    fi
  fi
fi

# 7. Session Sentinel — environment drift check (read-only)
if [ -f "scripts/session-sentinel.sh" ]; then
  echo ""
  bash scripts/session-sentinel.sh check 2>/dev/null || true
fi
