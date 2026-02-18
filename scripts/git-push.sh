#!/bin/bash
# Direct push to GitHub via PAT — bypasses Replit Git panel
# Usage: bash scripts/git-push.sh
#
# CRITICAL: This is the ONLY permitted method to push DnsToolWeb.
# NEVER use the GitHub API or Git panel to push this repo.
# See SKILL.md "Repo Sync Law" for why.
#
# LOCK FILES ARE MISSION-CRITICAL BLOCKERS.
# This script HARD-STOPS if ANY lock files exist.
# Run 'bash scripts/git-health-check.sh' first to clear them.

cd /home/runner/workspace

REPO="careyjames/DnsToolWeb"
BRANCH="main"
PAT_URL="https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git"

if [ -z "$CAREY_PAT_ALL3_REPOS" ]; then
  echo "ABORT: CAREY_PAT_ALL3_REPOS secret not set"
  exit 1
fi

# ── GATE 1: Lock files — HARD STOP if any exist ──
# Lock files cause PUSH_REJECTED, stalled rebases, corrupted git state.
# They cost nearly a day of production in Feb 2026. Zero tolerance.
echo "=== GATE 1: Lock file check ==="
LOCK_FILES=$(find .git -name "*.lock" -type f 2>/dev/null || true)
if [ -n "$LOCK_FILES" ]; then
  LOCK_COUNT=$(echo "$LOCK_FILES" | wc -l)
  echo ""
  echo "  HARD STOP: ${LOCK_COUNT} lock file(s) found:"
  echo "$LOCK_FILES" | sed 's/^/    /'
  echo ""
  echo "  Lock files are mission-critical blockers. Fix before pushing."
  echo ""
  echo "  Run this in the Shell tab:"
  echo "    bash scripts/git-health-check.sh"
  echo ""
  echo "  Then re-run this push script."
  exit 1
fi
echo "  PASS — zero lock files"

# ── GATE 2: No interrupted rebase ──
echo "=== GATE 2: Rebase state check ==="
if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ]; then
  echo ""
  echo "  HARD STOP: Interrupted rebase detected."
  echo ""
  echo "  Run this in the Shell tab:"
  echo "    bash scripts/git-health-check.sh"
  echo ""
  echo "  Then re-run this push script."
  exit 1
fi
echo "  PASS — no interrupted rebase"

# ── GATE 3: No intel files in public repo ──
echo "=== GATE 3: Intel file safety check ==="
INTEL_FILES=$(find go-server -name "*_intel*" 2>/dev/null || true)
if [ -n "$INTEL_FILES" ]; then
  echo ""
  echo "  HARD STOP: Intel files found in public repo!"
  echo "$INTEL_FILES" | sed 's/^/    /'
  echo ""
  echo "  Push these to dnstool-intel via sync script and delete locally."
  exit 1
fi
echo "  PASS — no intel files"

# ── All gates passed — proceed with push ──
echo ""
echo "=== All safety gates passed ==="
echo ""

# ── Show what's being pushed ──
AHEAD=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
echo "Commits ahead of origin/${BRANCH}: ${AHEAD}"

if [ "$AHEAD" = "0" ]; then
  echo "Nothing to push — already synced."
  exit 0
fi

git log --oneline origin/${BRANCH}..HEAD

# ── Push via PAT ──
echo ""
echo "Pushing to github.com/${REPO} ${BRANCH}..."
if ! git push "${PAT_URL}" ${BRANCH}; then
  echo ""
  echo "PUSH FAILED. Troubleshoot:"
  echo "  1. Run 'bash scripts/git-health-check.sh' from Shell tab"
  echo "  2. Check if branches diverged (may need force push — see SKILL.md)"
  echo "  3. Verify PAT is valid: CAREY_PAT_ALL3_REPOS"
  exit 1
fi

# ── Update tracking ref ──
echo ""
echo "=== Updating tracking ref ==="
FETCH_URL="https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git"
if git fetch "$FETCH_URL" ${BRANCH} 2>/dev/null; then
  REMAINING=$(git rev-list origin/${BRANCH}..HEAD --count 2>/dev/null || echo "?")
  if [ "$REMAINING" = "0" ]; then
    echo "  FULLY SYNCED — zero commits ahead, tracking ref current."
  else
    echo "  Tracking ref updated. ${REMAINING} local commits ahead (unpushed checkpoints)."
  fi
else
  echo "  Push succeeded but fetch failed (likely new lock file from background maintenance)."
  echo "  To fully sync tracking ref, run from Shell tab:"
  echo "    bash scripts/git-health-check.sh && git fetch"
fi
echo ""
echo "PUSH COMPLETE."
