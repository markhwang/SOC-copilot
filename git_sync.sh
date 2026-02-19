#!/bin/bash
# ============================================================
#  SOC Copilot — Quick GitHub Sync
#  Stages all changes, commits, and pushes to origin/main.
#  Run this whenever you want to sync work to GitHub.
# ============================================================

set -e

# Friendly commit message (edit or pass as first arg)
MSG="${1:-sync: update from Cowork session $(date '+%Y-%m-%d %H:%M')}"

echo "→ Staging all changes..."
git add .

# Only commit if there's something staged
if git diff --cached --quiet; then
  echo "✓  Nothing new to commit — already up to date."
else
  echo "→ Committing: \"$MSG\""
  git commit -m "$MSG"
  echo "→ Pushing to origin/main..."
  git push origin main
  echo "✅  Synced to https://github.com/markhwang/SOC-copilot"
fi
