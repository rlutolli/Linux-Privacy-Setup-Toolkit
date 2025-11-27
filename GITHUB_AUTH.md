# GitHub Authentication Setup

GitHub no longer accepts passwords. You need to use either:
1. **Personal Access Token (PAT)** - Easier, works with HTTPS
2. **SSH Key** - More secure, works with SSH URLs

## Option 1: Personal Access Token (Recommended - Easier)

### Step 1: Create a Personal Access Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Give it a name like "Linux Privacy Toolkit"
4. Select scopes:
   - ✅ `repo` (full control of private repositories)
5. Click "Generate token"
6. **COPY THE TOKEN IMMEDIATELY** (you won't see it again!)

### Step 2: Switch back to HTTPS and use the token

```bash
cd "/home/rlutolli/Downloads/Linux-Privacy-Setup-Toolkit-main/Linux Privacy Setup Toolkit"

# Switch back to HTTPS
git remote set-url origin https://github.com/rlutolli/Linux-Privacy-Setup-Toolkit.git

# Push (it will ask for username and password)
# Username: rlutolli
# Password: PASTE_YOUR_TOKEN_HERE (not your GitHub password!)
git push -u origin main
```

### Step 3: (Optional) Save token to avoid entering it every time

```bash
# Install git credential helper
git config --global credential.helper store

# On first push, enter your token as password
# It will be saved for future use
```

---

## Option 2: SSH Key (More Secure)

### Step 1: Add your SSH key to GitHub

Your SSH public key is:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEhKbPPCcY/bW2O/ytA8Se6y5tKSNgPBAJMrpScJbqT5 rlutolli@york.citycollege.eu
```

1. Copy the key above (or run: `cat ~/.ssh/id_ed25519.pub`)
2. Go to https://github.com/settings/keys
3. Click "New SSH key"
4. Title: "Linux Privacy Toolkit"
5. Key: Paste your public key
6. Click "Add SSH key"

### Step 2: Test and push

```bash
cd "/home/rlutolli/Downloads/Linux-Privacy-Setup-Toolkit-main/Linux Privacy Setup Toolkit"

# Test SSH connection
ssh -T git@github.com
# Should say: "Hi rlutolli! You've successfully authenticated..."

# Push (already configured for SSH)
git push -u origin main
```

---

## Current Setup

Your repository is already configured for SSH:
- Remote URL: `git@github.com:rlutolli/Linux-Privacy-Setup-Toolkit.git`

If SSH doesn't work (network/firewall), use Option 1 (Personal Access Token) instead.

