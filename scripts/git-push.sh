#!/bin/bash
# Direct push to GitHub via PAT — bypasses Replit Git panel
# Usage: bash scripts/git-push.sh
#
# CRITICAL: This is the ONLY permitted method to push DnsToolWeb.
# NEVER use the GitHub API or Git panel to push this repo.
# See SKILL.md "Repo Sync Law" for why.
#
# LOCK FILES: Smart classification — only push-blocking locks (index, HEAD,
# config, shallow) cause HARD STOP. Background locks (maintenance, refs/remotes)
# are logged as INFO and do NOT block the push.
#
# SYNC VERIFICATION uses git ls-remote (read-only) instead of git fetch,
# because the Replit platform blocks .git writes from the agent process tree.
# NOTE: .git/objects/maintenance.lock is EXPECTED to be present — it's
# Replit's background git maintenance, not a stale lock. It does NOT block push.

cd /home/runner/workspace

REPO="careyjames/DnsToolWeb"
BRANCH="main"
PAT_URL="https://${CAREY_PAT_ALL3_REPOS}@github.com/${REPO}.git"

if [ -z "$CAREY_PAT_ALL3_REPOS" ]; then
  echo "ABORT: CAREY_PAT_ALL3_REPOS secret not set"
  exit 1
fi

# ── GATE 1: Lock files — distinguish push-blocking from harmless ──
# Push-blocking locks: index.lock, HEAD.lock, config.lock, shallow.lock
# Harmless for push: maintenance.lock (Replit background), refs/remotes/* (tracking refs)
echo "=== GATE 1: Lock file check ==="
ALL_LOCKS=$(find .git -name "*.lock" -type f 2>/dev/null || true)
PUSH_BLOCKERS=""
HARMLESS=""

if [ -n "$ALL_LOCKS" ]; then
  while IFS= read -r lockfile; do
    case "$lockfile" in
      .git/index.lock|.git/HEAD.lock|.git/config.lock|.git/shallow.lock)
        PUSH_BLOCKERS="${PUSH_BLOCKERS}${lockfile}\n"
        ;;
      *)
        HARMLESS="${HARMLESS}${lockfile}\n"
        ;;
    esac
  done <<< "$ALL_LOCKS"
fi

if [ -n "$PUSH_BLOCKERS" ]; then
  echo ""
  echo "  HARD STOP: Push-blocking lock file(s) found:"
  echo -e "$PUSH_BLOCKERS" | sed '/^$/d' | sed 's/^/    /'
  echo ""
  echo "  These locks prevent git push. Fix before pushing."
  echo ""
  echo "  Run this in the Shell tab:"
  echo "    bash scripts/git-health-check.sh"
  echo ""
  echo "  Then re-run this push script."
  exit 1
fi

if [ -n "$HARMLESS" ]; then
  echo "  INFO: Non-blocking lock file(s) present (safe to ignore for push):"
  echo -e "$HARMLESS" | sed '/^$/d' | sed 's/^/    /'
fi
echo "  PASS — no push-blocking locks"

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

# ── All gates passed ──
echo ""
echo "=== All safety gates passed ==="
echo ""

# ── Pre-push: check what GitHub has vs what we have ──
LOCAL_SHA=$(git rev-parse HEAD 2>/dev/null)
REMOTE_SHA=$(git ls-remote "$PAT_URL" refs/heads/${BRANCH} 2>/dev/null | awk '{print $1}')

if [ "$LOCAL_SHA" = "$REMOTE_SHA" ]; then
  echo "Already synced — local HEAD ($LOCAL_SHA) matches GitHub."
  echo ""
  echo "SYNC STATUS: VERIFIED MATCH"
  exit 0
fi

echo "Local HEAD:  ${LOCAL_SHA}"
echo "GitHub HEAD: ${REMOTE_SHA:-"(unable to read)"}"
echo ""

# ── Show commits to push ──
git log --oneline "${REMOTE_SHA}..HEAD" 2>/dev/null || git log --oneline -5

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

# ── Verify sync via ls-remote (read-only — no .git writes) ──
echo ""
echo "=== Verifying sync (read-only) ==="
POST_PUSH_REMOTE=$(git ls-remote "$PAT_URL" refs/heads/${BRANCH} 2>/dev/null | awk '{print $1}')

if [ "$LOCAL_SHA" = "$POST_PUSH_REMOTE" ]; then
  echo "  VERIFIED: Local HEAD matches GitHub HEAD."
  echo "  Local:  $LOCAL_SHA"
  echo "  GitHub: $POST_PUSH_REMOTE"
  echo ""
  echo "SYNC STATUS: FULLY SYNCED"
else
  echo "  WARNING: SHA mismatch after push."
  echo "  Local:  $LOCAL_SHA"
  echo "  GitHub: ${POST_PUSH_REMOTE:-"(unable to read)"}"
  echo "  This may indicate a new checkpoint was created during push."
fi
echo ""
echo "PUSH COMPLETE."
