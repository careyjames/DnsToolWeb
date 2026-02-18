#!/bin/bash
# Session Sentinel — Environment Drift Detection
# Detects when the Replit platform changes project files between sessions.
#
# Usage:
#   bash scripts/session-sentinel.sh snapshot   # Save current file state
#   bash scripts/session-sentinel.sh check      # Compare against last snapshot
#   bash scripts/session-sentinel.sh report     # Show last snapshot info
#
# IMPORTANT: This is INTERNAL dev tooling (.drift/).
# Completely separate from the DNS drift engine (user-facing posture_hash).

set -euo pipefail
cd /home/runner/workspace

DRIFT_DIR=".drift"
MANIFEST="$DRIFT_DIR/manifest.json"

WATCHED_FILES=(
  "go.mod"
  "go.sum"
  "package.json"
  "package-lock.json"
  "build.sh"
  "main.py"
  ".replit"
  "replit.nix"
  "replit.md"
  "PROJECT_CONTEXT.md"
  "DRIFT_ENGINE.md"
  "go-server/internal/config/config.go"
  "go-server/db/schema/schema.sql"
  "static/css/custom.css"
  "static/css/custom.min.css"
  "static/manifest.json"
  "scripts/git-push.sh"
  "scripts/git-health-check.sh"
  "scripts/git-panel-reset.sh"
)

BINARY="dns-tool-server"

hash_file() {
  if [ -f "$1" ]; then
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
  else
    echo "MISSING"
  fi
}

file_size() {
  if [ -f "$1" ]; then
    stat -c%s "$1" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

file_mtime() {
  if [ -f "$1" ]; then
    stat -c%Y "$1" 2>/dev/null || echo "0"
  else
    echo "0"
  fi
}

count_templates() {
  find go-server/templates -name "*.html" -type f 2>/dev/null | wc -l
}

count_go_files() {
  find go-server -name "*.go" -type f 2>/dev/null | wc -l
}

build_manifest() {
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local tpl_count
  tpl_count=$(count_templates)
  local go_count
  go_count=$(count_go_files)

  printf '{\n'
  printf '  "timestamp": "%s",\n' "$ts"
  printf '  "files": {\n'

  local first=true
  for f in "${WATCHED_FILES[@]}"; do
    local h s m
    h=$(hash_file "$f")
    s=$(file_size "$f")
    m=$(file_mtime "$f")
    if [ "$first" = true ]; then
      first=false
    else
      printf ',\n'
    fi
    printf '    "%s": {"sha256":"%s","size":%s,"mtime":%s}' "$f" "$h" "$s" "$m"
  done

  if [ -f "$BINARY" ]; then
    local bs bm
    bs=$(file_size "$BINARY")
    bm=$(file_mtime "$BINARY")
    printf ',\n'
    printf '    "%s": {"sha256":"BINARY_SKIP","size":%s,"mtime":%s}' "$BINARY" "$bs" "$bm"
  fi

  printf '\n  },\n'
  printf '  "meta": {\n'
  printf '    "template_count": %s,\n' "$tpl_count"
  printf '    "go_file_count": %s,\n' "$go_count"
  printf '    "watched_files": %s\n' "${#WATCHED_FILES[@]}"
  printf '  }\n'
  printf '}\n'
}

cmd_snapshot() {
  mkdir -p "$DRIFT_DIR"
  build_manifest > "$MANIFEST"
  local tpl_count go_count
  tpl_count=$(count_templates)
  go_count=$(count_go_files)
  echo "Session Sentinel: snapshot saved"
  echo "  Watched files: ${#WATCHED_FILES[@]} + binary"
  echo "  Templates: $tpl_count | Go files: $go_count"
  echo "  Manifest: $MANIFEST"
}

cmd_check() {
  if [ ! -f "$MANIFEST" ]; then
    echo "Session Sentinel: no previous snapshot found"
    echo "  Run: bash scripts/session-sentinel.sh snapshot"
    return 0
  fi

  local prev_ts
  prev_ts=$(grep '"timestamp"' "$MANIFEST" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
  echo "Session Sentinel: checking against snapshot from $prev_ts"
  echo ""

  local changed=0
  local added=0
  local deleted=0
  local unchanged=0
  local details=""

  for f in "${WATCHED_FILES[@]}"; do
    local current_hash
    current_hash=$(hash_file "$f")

    local prev_hash
    prev_hash=$(grep -A1 "\"$f\"" "$MANIFEST" 2>/dev/null | grep sha256 | head -1 | sed 's/.*"sha256":"\([^"]*\)".*/\1/' || echo "")

    if [ -z "$prev_hash" ]; then
      if [ "$current_hash" != "MISSING" ]; then
        added=$((added+1))
        details="${details}  + ADDED:    $f\n"
      fi
    elif [ "$current_hash" = "MISSING" ] && [ "$prev_hash" != "MISSING" ]; then
      deleted=$((deleted+1))
      details="${details}  - DELETED:  $f\n"
    elif [ "$current_hash" != "$prev_hash" ]; then
      changed=$((changed+1))
      details="${details}  ~ CHANGED:  $f\n"
    else
      unchanged=$((unchanged+1))
    fi
  done

  if [ -f "$BINARY" ]; then
    local current_size prev_size
    current_size=$(file_size "$BINARY")
    prev_size=$(grep -A1 "\"$BINARY\"" "$MANIFEST" 2>/dev/null | grep '"size"' | head -1 | sed 's/.*"size":\([0-9]*\).*/\1/' || echo "0")
    if [ "$current_size" != "$prev_size" ] && [ -n "$prev_size" ] && [ "$prev_size" != "0" ]; then
      changed=$((changed+1))
      details="${details}  ~ CHANGED:  $BINARY (size: ${prev_size} → ${current_size})\n"
    else
      unchanged=$((unchanged+1))
    fi
  fi

  local prev_tpl new_tpl prev_go new_go
  prev_tpl=$(grep '"template_count"' "$MANIFEST" 2>/dev/null | head -1 | sed 's/[^0-9]//g' || echo "0")
  new_tpl=$(count_templates)
  prev_go=$(grep '"go_file_count"' "$MANIFEST" 2>/dev/null | head -1 | sed 's/[^0-9]//g' || echo "0")
  new_go=$(count_go_files)

  if [ "$prev_tpl" != "$new_tpl" ]; then
    details="${details}  ~ META:     template count $prev_tpl → $new_tpl\n"
  fi
  if [ "$prev_go" != "$new_go" ]; then
    details="${details}  ~ META:     Go file count $prev_go → $new_go\n"
  fi

  local total=$((changed + added + deleted))
  if [ "$total" -eq 0 ]; then
    echo "  CLEAN — no drift detected ($unchanged files unchanged)"
  else
    echo "  DRIFT DETECTED: $changed changed, $added added, $deleted deleted ($unchanged unchanged)"
    echo ""
    printf "%b" "$details"
  fi
}

cmd_report() {
  if [ ! -f "$MANIFEST" ]; then
    echo "Session Sentinel: no snapshot exists yet"
    echo "  Run: bash scripts/session-sentinel.sh snapshot"
    return 0
  fi

  local ts watched tpl_count go_count
  ts=$(grep '"timestamp"' "$MANIFEST" | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/')
  watched=$(grep '"watched_files"' "$MANIFEST" | head -1 | sed 's/[^0-9]//g')
  tpl_count=$(grep '"template_count"' "$MANIFEST" | head -1 | sed 's/[^0-9]//g')
  go_count=$(grep '"go_file_count"' "$MANIFEST" | head -1 | sed 's/[^0-9]//g')

  echo "Session Sentinel: last snapshot"
  echo "  Timestamp:    $ts"
  echo "  Watched:      $watched files + binary"
  echo "  Templates:    $tpl_count"
  echo "  Go files:     $go_count"
  echo "  Manifest:     $MANIFEST"
}

case "${1:-help}" in
  snapshot) cmd_snapshot ;;
  check)    cmd_check ;;
  report)   cmd_report ;;
  *)
    echo "Usage: bash scripts/session-sentinel.sh {snapshot|check|report}"
    echo ""
    echo "  snapshot  Save current file state (run after push or at session end)"
    echo "  check     Compare current state against last snapshot"
    echo "  report    Show info about last snapshot"
    ;;
esac
