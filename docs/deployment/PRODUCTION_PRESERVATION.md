# Production Preservation — Pre-Demo-Mode Baseline

**Date recorded:** 2026-10-28. **Why this document exists:** before merging Demo Mode and the
VTEM audit documentation into `main`, we needed a verified, pushable reference to the exact
code currently running in production, so a bad merge or an unwanted auto-deploy can be reverted
without guessing.

## Verified production commit

**`48747baebc0746d42751c59284743d97c45d935e`** (short: `48747ba`) — "Merge
sprint3/frontend-collector-validation into main."

This is not assumed — it was confirmed live, directly from the running services, on 2026-10-28:

- **Backend (Render):** `GET https://novrsoc.onrender.com/health` returned
  `{"status":"healthy","version":"48747baebc07"}`. The backend's own `/health` handler
  (`backend/src/index.ts`) reports `RAILWAY_GIT_COMMIT_SHA || RENDER_GIT_COMMIT`, so this is the
  exact deployed commit, not an inference. It matches `origin/main`'s tip exactly — **no drift**.
- **Frontend (Vercel):** `https://novr-soc.vercel.app/` is live (HTTP 200) and serves the real
  product. Its compiled JS bundle has `NEXT_PUBLIC_BACKEND_URL` inlined as
  `https://novrsoc.onrender.com` — the same backend just confirmed at `48747ba` — which is strong
  circumstantial evidence the frontend build is from the same commit (Vercel's standard behavior
  is to auto-deploy its configured production branch, ordinarily `main`, on every push, and no
  newer commit had been pushed to `origin/main` at the time of this check). There is **no
  frontend-exposed build-id or version endpoint**, so this could not be confirmed byte-exact the
  way the backend was — flagged honestly, not glossed over.
- Three other candidate URLs were checked and found dead/unrelated, recorded so nobody wastes
  time on them again: `https://novrsoc-production-1fb6.up.railway.app` (Railway — "Application
  not found," the service no longer exists at that hostname), `https://socnovr.vercel.app` and
  `https://novrsoc.vercel.app` (both Vercel `DEPLOYMENT_NOT_FOUND`). `https://novrsoc-prev.vercel.app`
  is also dead (404).

## Preservation branch

**`production-stable-pre-demo`** — created locally, pointed exactly at `origin/main`
(`48747baebc0746d42751c59284743d97c45d935e`). **As of this writing it has not been pushed to
`origin`** — see the blocker recorded in the consolidation report. Push it with:

```
git push origin production-stable-pre-demo:refs/heads/production-stable-pre-demo
```

Frontend and backend SHAs were not found to differ, so a single preservation branch covers both
services; if that changes before this is pushed, re-verify and record two separately.

## Rollback procedure

If a future `main` push causes a bad deploy (Vercel) or a manually-triggered bad deploy (Render,
`autoDeploy: false` so this requires a deliberate dashboard action either way):

1. **Vercel:** in the project dashboard, find the deployment built from commit `48747ba` (or
   redeploy `production-stable-pre-demo` directly) and promote it to production, or change the
   project's Production Branch setting to `production-stable-pre-demo` temporarily.
2. **Render:** in the dashboard, select the `novrsoc-backend` service and manually deploy commit
   `48747ba` (or the `production-stable-pre-demo` branch) — nothing auto-deploys here
   (`autoDeploy: false` in `render.yaml` for both the backend and frontend blueprint entries), so
   this is always a deliberate action, not an emergency race against an automatic rollout.
3. Confirm recovery the same way this document was built: `curl https://novrsoc.onrender.com/health`
   should report `"version":"48747baebc07"` again, and the frontend should serve without error.

## What this document does not cover

Whether Vercel's project is configured to auto-deploy from `main` specifically (as opposed to
some other branch) could not be verified or changed from this environment — no Vercel API token,
CLI session, or dashboard access was available. This is the blocker recorded in the consolidation
report: until it's resolved, pushing a new `main` commit carries an unverified risk of
auto-deploying Demo Mode to production. See that report before pushing.
