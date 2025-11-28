#!/bin/bash
# Safe script to remove personal information from git history
# Creates backup first, then rewrites history

set -e

REPO_DIR="$(pwd)"
BACKUP_DIR="${REPO_DIR}_backup_$(date +%Y%m%d_%H%M%S)"

echo "🔒 Removing personal information from git history"
echo ""
echo "⚠️  This will:"
echo "   1. Create a backup: $BACKUP_DIR"
echo "   2. Rewrite all commit history to remove personal info"
echo "   3. Change all author names/emails to generic values"
echo ""
read -p "Continue? [y/N]: " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

# Step 1: Create backup
echo "📦 Creating backup..."
cp -r "$REPO_DIR" "$BACKUP_DIR"
echo "✓ Backup created: $BACKUP_DIR"

# Step 2: Check if git-filter-repo is available (modern, recommended)
if command -v git-filter-repo &> /dev/null; then
    echo "✓ Using git-filter-repo (modern method)"
    git filter-repo --name-callback 'return b"Privacy Toolkit Contributor"' \
                     --email-callback 'return b"privacy-toolkit@example.com"' \
                     --force
else
    echo "⚠️  git-filter-repo not found, using git filter-branch (slower)"
    echo "   Install git-filter-repo for better performance: pip install git-filter-repo"
    
    # Use filter-branch as fallback
    git filter-branch --env-filter '
        export GIT_AUTHOR_NAME="Privacy Toolkit Contributor"
        export GIT_AUTHOR_EMAIL="privacy-toolkit@example.com"
        export GIT_COMMITTER_NAME="Privacy Toolkit Contributor"
        export GIT_COMMITTER_EMAIL="privacy-toolkit@example.com"
    ' --tag-name-filter cat -- --branches --tags
    
    # Clean up
    rm -rf .git/refs/original/
    git reflog expire --expire=now --all
    git gc --prune=now --aggressive
fi

echo ""
echo "✓ Git history rewritten!"
echo ""
echo "📋 Next steps:"
echo "   1. Review the changes: git log"
echo "   2. If everything looks good, force push:"
echo "      git push --force origin main"
echo ""
echo "⚠️  WARNING: Force pushing will overwrite remote history!"
echo "   Make sure you're ready before pushing."
echo ""
echo "💾 Backup location: $BACKUP_DIR"
