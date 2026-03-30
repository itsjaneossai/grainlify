# Vercel Deployment Setup Guide

## Overview

This guide explains how to set up Grainlify for deployment on Vercel through GitHub Actions. The deployment workflow automates production and preview deployments automatically on push and pull requests.

## Prerequisites

1. Vercel account with admin access
2. GitHub repository administrator access
3. Frontend and Website projects already created in Vercel

## Step 1: Create Vercel Token

1. Log in to [Vercel Dashboard](https://vercel.com/dashboard)
2. Go to **Settings** → **Tokens**
3. Click **Create Token**
4. Set name: `grainlify-github-actions`
5. Select scope: **Full Account**
6. Click **Create Token**
7. **Copy the token** (you won't see it again)

## Step 2: Get Vercel Organization ID

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. In the sidebar, hover over your team/account name
3. Look for the ID format: `tm_` or `acct_`
4. Or navigate to Settings → General and find **ID** field
5. **Copy the Organization/Team ID**

## Step 3: Get Vercel Project IDs

For each project (frontend, website):

1. Go to the project in [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **Settings**
3. Find the **Project ID** field
4. **Copy the Project ID**

Repeat for both:
- `VERCEL_PROJECT_ID_FRONTEND` - ID from frontend project
- `VERCEL_PROJECT_ID_WEBSITE` - ID from website project

## Step 4: Add Secrets to GitHub

### Via GitHub Web UI:

1. Go to GitHub repository
2. Click **Settings** tab
3. Go to **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Add each secret:

| Secret Name | Value |
|---|---|
| `VERCEL_TOKEN` | Your Vercel token from Step 1 |
| `VERCEL_ORG_ID` | Your organization ID from Step 2 |
| `VERCEL_PROJECT_ID_FRONTEND` | Frontend project ID from Step 3 |
| `VERCEL_PROJECT_ID_WEBSITE` | Website project ID from Step 3 |

### Via GitHub CLI:

```bash
gh secret set VERCEL_TOKEN --body "your_token_here"
gh secret set VERCEL_ORG_ID --body "your_org_id"
gh secret set VERCEL_PROJECT_ID_FRONTEND --body "frontend_project_id"
gh secret set VERCEL_PROJECT_ID_WEBSITE --body "website_project_id"
```

## Step 5: Configure Vercel Projects

### Environment Variables

For each Vercel project, ensure the following are configured:

#### Frontend Project Environment Variables:
```
VITE_API_URL=https://api.grainlify.com
VITE_APP_ENV=production
```

#### Website Project Environment Variables:
```
NEXT_PUBLIC_APP_ENV=production
```

### Build & Development Settings

**Frontend:**
- Framework: Vite
- Build Command: `npm run build`
- Output Directory: `dist`

**Website:**
- Framework: Next.js
- Build Command: `npm run build`
- Output Directory: `.next`

## Step 6: Test Deployment

### Test with a Pull Request:
1. Create a new feature branch
2. Make some changes to `frontend/` or `website/`
3. Push branch and create a PR
4. GitHub Actions will create a preview deployment
5. Check PR comments for preview URLs

### Test Production Deployment:
1. Merge PR or push directly to `main`
2. Check GitHub Actions for deployment status
3. Verify deployment in Vercel Dashboard

## Deployment Workflow

### File: `.github/workflows/vercel-deploy.yml`

The workflow automatically:

**On Push to main/develop/master (Production):**
- Deploys frontend to production
- Deploys website to production
- Creates permanent production URLs

**On PR to main/develop/master (Preview):**
- Creates preview deployments with unique URLs
- Comments on PR with preview links
- Allows testing before merging

## Troubleshooting

### "Authorization required to deploy"
- ✅ Verify `VERCEL_TOKEN` is set and has proper permissions
- ✅ Check token hasn't expired
- ✅ Verify `VERCEL_ORG_ID` matches Vercel account

### Deployment fails silently
- Check GitHub Actions logs: **Actions** → select workflow → view logs
- Verify all environment variables are set
- Check Vercel project settings match workflow expectations

### Wrong project deploying
- Verify `VERCEL_PROJECT_ID_FRONTEND` and `VERCEL_PROJECT_ID_WEBSITE` IDs
- Check that frontend is deploying to frontend project, website to website project

### Build fails in Vercel
- Ensure all dependencies are correct
- Check build scripts in `package.json`
- Verify environment variables are set in Vercel project settings

## Secrets Rotation

To rotate the Vercel token periodically:

1. In Vercel, create a new token
2. In GitHub, update `VERCEL_TOKEN` secret with new token
3. In Vercel, delete the old token

## Preview Deployment URLs

Preview URLs follow this format:
```
https://grainlify-git-branch-name-deployer-username.vercel.app
```

## Production URLs

Production URLs depend on your Vercel domain:
```
https://grainlify.com (main domain)
or
https://grainlify-prod.vercel.app (Vercel domain)
```

## Resources

- [Vercel API Documentation](https://vercel.com/docs/rest-api)
- [GitHub Actions Secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
- [Vercel Deployments](https://vercel.com/docs/deployments)
