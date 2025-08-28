# Simple GitHub Setup Guide

## 🔐 Quick Setup (3 Steps)

### Step 1: Create GitHub Token
1. Go to: https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Set **Note**: `Secure-Redirect-Worker`
4. Select **Scopes**: ✅ `repo` only
5. Click "Generate token" and **copy the token**

### Step 2: Set Environment Variables
```bash
# Set your GitHub token
wrangler secret put GITHUB_API_TOKEN
# Enter your token when prompted

# Set repository details
wrangler secret put GITHUB_REPO_OWNER
# Enter: docxsigned

wrangler secret put GITHUB_REPO_NAME  
# Enter: secure-redirect-landing

wrangler secret put GITHUB_BRANCH
# Enter: main
```

### Step 3: Deploy
```bash
wrangler deploy
```

## ✅ What's New

| Feature | Before | After |
|---------|--------|-------|
| **Data Source** | Hardcoded in code | GitHub repository |
| **Rate Limits** | None | 10 requests/minute per IP |
| **Caching** | None | 5-minute cache |
| **Security** | Basic | Enhanced with authentication |

## 🔧 Environment Variables

| Variable | Value | Purpose |
|----------|-------|---------|
| `GITHUB_API_TOKEN` | Your token | GitHub API access |
| `GITHUB_REPO_OWNER` | `docxsigned` | Repository owner |
| `GITHUB_REPO_NAME` | `secure-redirect-landing` | Repository name |
| `GITHUB_BRANCH` | `main` | Branch name |

## 📊 Benefits

- **Security**: No hardcoded data in worker
- **Performance**: 5-minute caching reduces API calls
- **Scalability**: Easy to update data via GitHub
- **Rate Limiting**: Prevents abuse (10 req/min per IP)

## 🔄 Update Data

To update emails, URLs, or blacklist:
1. Edit files in your GitHub repository
2. Commit and push changes
3. Data updates automatically within 5 minutes

## 🛠️ Troubleshooting

**If it's not working:**
```bash
# Check logs
wrangler tail

# Verify environment variables
wrangler secret list

# Test deployment
wrangler deploy
```

**Common issues:**
- ❌ **Rate limit errors**: Add GitHub token
- ❌ **Cache not working**: Check KV namespace
- ❌ **Data not updating**: Wait 5 minutes for cache refresh 