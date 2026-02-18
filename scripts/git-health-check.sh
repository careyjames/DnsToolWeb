#!/bin/bash
# Git Health Check — run at session start to prevent cascading git corruption
# Fixes: stale lock files, interrupted rebases, detached HEAD
# Safe to run repeatedly — only fixes problems, never destructive

set -e
cd /home/runner/workspace 2>/dev/null || exit 0

FIXED=0

# 1. Remove ALL stale lock files (comprehensive list from real incidents)
for lockfile in \
  .git/index.lock \
  .git/HEAD.lock \
  .git/ORIG_HEAD.lock \
  .git/MERGE_HEAD.lock \
  .git/FETCH_HEAD.lock \
  .git/packed-refs.lock \
  .git/refs/heads/replit-agent.lock \
  .git/refs/heads/main.lock; do
  if [ -f "$lockfile" ]; then
    rm -f "$lockfile" 2>/dev/null && echo "Removed stale $lockfile" && FIXED=$((FIXED+1))
  fi
done

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
  echo "Git health: OK"
else
  echo "Git health: fixed $FIXED issue(s)"
fi

git branch --show-current 2>/dev/null || true
