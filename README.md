# KeyWatch

Exposed API key monitor. Scans newly issued domains from Certificate
Transparency logs, verifies secrets with TruffleHog, and serves a dashboard.

## Deploy

### 1. GitHub repo
- Create a repo (public or private).
- Push all files.
- Go to **Settings → Actions → General** and ensure "Read and write permissions"
  is enabled under Workflow permissions.
- Trigger the workflow manually once from the **Actions** tab to seed `data/`.

### 2. Render dashboard
- New **Web Service** → connect the repo.
- Runtime: Python.
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 120`
- Plan: Free.
- (Optional) Add env var `RESULTS_JSON_URL` pointing to the raw GitHub URL
  of `data/results.json` if the repo is public. If private, leave it unset —
  Render will read the local file that ships with each deploy.

### 3. Schedule
- The workflow runs every 6 hours automatically.
- Adjust `TLDS`, `HOURS`, and `MAX_DOMAINS` in `.github/workflows/scan.yml`.

## Notes
- Render's free web service spins down after 15 minutes of idle. It will cold
  start on the next visit.
- TruffleHog is installed only in GitHub Actions, not on Render.
- Keys are truncated in the dashboard. Full secrets are never stored.
