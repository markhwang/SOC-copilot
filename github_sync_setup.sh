#!/bin/bash
# ============================================================
#  SOC Copilot — GitHub Sync Setup
#  Run this ONCE from your Mac terminal inside your project folder.
#
#  Step 1: Create a GitHub PAT (if you haven't already)
#    → github.com → Settings → Developer Settings
#      → Personal access tokens → Tokens (classic) → Generate new token
#    → Scopes needed: check "repo" (full control of private repositories)
#    → Copy the token (starts with ghp_...)
#
#  Step 2: Paste your token below and run this script.
# ============================================================

GITHUB_TOKEN="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"        # ← paste your token here (ghp_xxxxxxxxxxxx)
GITHUB_USER="markhwang"
REPO_NAME="SOC-copilot"
REMOTE_URL="https://${GITHUB_TOKEN}@github.com/${GITHUB_USER}/${REPO_NAME}.git"

# ---------------------------------------------------------------
if [ -z "$GITHUB_TOKEN" ]; then
  echo "❌  Please open this script and set GITHUB_TOKEN before running."
  exit 1
fi

echo "→ Cleaning up any stale git lock files..."
rm -f .git/index.lock .git/objects/maintenance.lock 2>/dev/null || true

echo "→ Initializing git repository (if needed)..."
git init

echo "→ Switching to 'main' branch..."
git checkout -b main 2>/dev/null || git checkout main

echo "→ Configuring remote with credentials..."
git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE_URL"

echo "→ Fetching existing history from GitHub..."
git fetch origin

echo "→ Merging GitHub history (keeping all local files)..."
git merge --allow-unrelated-histories -m "chore: merge GitHub history with local workspace" origin/main 2>/dev/null || \
  git reset --soft origin/main

echo "→ Staging all local files..."
git add .

echo "→ Creating initial sync commit..."
git diff --cached --quiet || git commit -m "chore: initial local files (requirements.txt, .env.example, empty dirs)"

echo "→ Pushing to GitHub..."
git push -u origin main

echo ""
echo "✅  Done! Your project is now synced to GitHub."
echo "   Future syncs: run ./git_sync.sh"
