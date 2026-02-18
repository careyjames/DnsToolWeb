#!/bin/bash
# Direct push to GitHub via PAT — bypasses Replit Git panel and lock files
# Usage: bash scripts/git-push.sh
#
# CRITICAL: This is the ONLY permitted method to push DnsToolWeb.
# NEVER use the GitHub API or Git panel to push this repo.
# See SKILL.md "Repo Sync Law" for why.

cd /home/runner/workspace

REPO="careyjames/DnsToolWeb"
BRANCH="main"
PAT_URL="https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git"

if [ -z "$CAREY_PAT_ALL3_REPOS" ]; then
  echo "Error: CAREY_PAT_ALL3_REPOS secret not set"
  exit 1
fi

# ── STEP 1: Detect stale lock files (report only — don't attempt removal) ──
# Lock cleanup lives in git-health-check.sh, run by the user from Shell tab.
# The Replit platform kills the agent's entire process tree if it touches .git files,
# so this script must NEVER attempt rm on .git paths. Locks don't block git push.
echo "=== Lock file status ==="
LOCK_FILES=$(find .git -name "*.lock" -type f 2>/dev/null || true)
if [ -z "$LOCK_FILES" ]; then
  echo "  Clean — no stale lock files"
else
  LOCK_COUNT=$(echo "$LOCK_FILES" | wc -l)
  echo "  WARNING: ${LOCK_COUNT} stale lock file(s) detected:"
  echo "$LOCK_FILES" | sed 's/^/    /'
  echo ""
  echo "  These don't block push, but block fetch/status/rebase."
  echo "  To clean: run 'bash scripts/git-health-check.sh' from the Shell tab."
  echo ""
fi

# ── STEP 2: Check for interrupted rebase (report only) ──
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  echo "=== WARNING: Interrupted rebase detected ==="
  echo "  Run 'bash scripts/git-health-check.sh' from Shell tab to abort and clean up."
  echo ""
fi

# ── STEP 3: Safety check — no intel files in public repo ──
echo "=== Intel file safety check ==="
INTEL_FILES=$(find go-server -name "*_intel*" 2>/dev/null || true)
if [ -n "$INTEL_FILES" ]; then
  echo "ABORT: Intel files found in public repo working directory!"
  echo "$INTEL_FILES"
  echo "Push these to dnstool-intel via sync script and delete locally BEFORE pushing."
  exit 1
fi
echo "  No intel files — safe to push"

# ── STEP 4: Check what needs pushing ──
AHEAD=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
echo ""
echo "Commits ahead of origin/${BRANCH}: ${AHEAD}"

if [ "$AHEAD" = "0" ]; then
  echo "Nothing to push."
  exit 0
fi

git log --oneline origin/${BRANCH}..HEAD

# ── STEP 5: Push via PAT ──
echo ""
echo "Pushing to github.com/${REPO} ${BRANCH}..."
if ! git push "${PAT_URL}" ${BRANCH}; then
  echo ""
  echo "PUSH FAILED. Common causes:"
  echo "  1. Stale lock files — run 'bash scripts/git-health-check.sh' from Shell tab"
  echo "  2. Diverged branches — may need force push (see SKILL.md)"
  echo "  3. PAT expired — check CAREY_PAT_ALL3_REPOS secret"
  exit 1
fi

# ── STEP 6: Update tracking ref ──
echo ""
echo "=== Post-push: updating tracking ref ==="
git fetch "${PAT_URL}" ${BRANCH} 2>/dev/null || true

# ── STEP 7: Verify sync ──
REMAINING=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
if [ "$REMAINING" = "0" ]; then
  echo "FULLY SYNCED — zero commits ahead, tracking ref updated."
else
  echo "Warning: tracking ref shows ${REMAINING} ahead. Run 'bash scripts/git-health-check.sh' in Shell tab to fix."
fi
