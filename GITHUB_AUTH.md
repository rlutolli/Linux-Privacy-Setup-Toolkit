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
cd /path/to/your/repository

# Switch to HTTPS (replace YOUR_USERNAME with your GitHub username)
git remote set-url origin https://github.com/YOUR_USERNAME/Linux-Privacy-Setup-Toolkit.git

# Push (it will ask for username and password)
# Username: YOUR_USERNAME
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

1. Get your SSH public key:
   ```bash
   cat ~/.ssh/id_ed25519.pub
   # Or if you use RSA:
   cat ~/.ssh/id_rsa.pub
   ```
2. Go to https://github.com/settings/keys
3. Click "New SSH key"
4. Title: "Linux Privacy Toolkit"
5. Key: Paste your public key
6. Click "Add SSH key"

### Step 2: Test and push

```bash
cd /path/to/your/repository

# Test SSH connection
ssh -T git@github.com
# Should say: "Hi YOUR_USERNAME! You've successfully authenticated..."

# Switch to SSH (replace YOUR_USERNAME)
git remote set-url origin git@github.com:YOUR_USERNAME/Linux-Privacy-Setup-Toolkit.git

# Push
git push -u origin main
```

---

## Current Setup

Check your current remote configuration:
```bash
git remote -v
```

If SSH doesn't work (network/firewall), use Option 1 (Personal Access Token) instead.
