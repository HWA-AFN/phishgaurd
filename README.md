# PhishGuard 2.0

A responsive Flask URL-risk assessment demo for an educational cybersecurity project.

## Run locally on macOS

```bash
cd PhishGuard_2.0
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Included
- Responsive dark cybersecurity landing page
- URL parsing and transparent heuristic checks
- Risk score with explanations
- Downloadable JSON scan report
- No external URL fetching

## Important limitations
This is a **rules-based prototype**, not a trained machine-learning model. It does not visit submitted websites, inspect page content, follow redirects, check certificates, or query threat-intelligence services. It can produce false positives and false negatives. A low score is not a safety guarantee.

## Before public deployment
Use a production WSGI server (such as Gunicorn), HTTPS, request-size limits, rate limiting, suitable security headers, and a clear data-retention policy. Do not add server-side URL fetching without SSRF protections, DNS/IP validation, redirect controls, and network egress restrictions. If adding ML, train and evaluate on a labeled dataset and report precision, recall, F1-score, and false-positive rate.
