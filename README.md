# PhishGuard Feather

A responsive Flask educational project for URL risk assessment. Feather combines explainable local URL heuristics with optional reputation lookups from Google Safe Browsing and VirusTotal.

## Run locally on macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Enable threat-intelligence providers

The app keeps API keys on the server. Never place them in browser JavaScript or commit them to GitHub.

- `GOOGLE_SAFE_BROWSING_API_KEY`: enables Google Safe Browsing URL lookups. Create/configure a key in Google Cloud and enable the Safe Browsing API for the project. See https://developers.google.com/safe-browsing/v4/reference/rest/v4/threatMatches/find
- `VIRUSTOTAL_API_KEY`: enables lookup of an existing VirusTotal URL report. This app only retrieves an existing report; it does not submit new URLs for scanning. VirusTotal states that queried indicators may be added to its dataset, so do not use this provider for confidential URLs. Review its current terms and quotas: https://docs.virustotal.com/docs/api-overview

If a key is missing, that provider is clearly shown as not configured. If a provider times out or returns an API error, the result marks the check unavailable rather than treating it as clean.

### Set keys in Render

Open Render → your PhishGuard service → **Environment** → **Add Environment Variable**. Add the variable name and key value, save, and redeploy. Do not add secrets to `render.yaml`, source code, or public GitHub files.

## How results work

- URL-pattern signals provide a heuristic risk score, not proof of maliciousness.
- A Google Safe Browsing match triggers a high-risk warning.
- VirusTotal malicious/suspicious detections are reported as reputation signals, with their limitations explained.
- “No known threats detected” does not mean a site is guaranteed safe. Newly created, targeted, or unreported malicious sites may not be listed.
- The app does not visit or crawl the destination website, follow redirects, inspect page content, or use a trained machine-learning model.

## Deployment

Render configuration is included in `render.yaml`. The web service uses `gunicorn app:app` and checks `/health`.
