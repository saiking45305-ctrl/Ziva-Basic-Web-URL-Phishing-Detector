# Ziva — Check before you click.

Ziva is a basic web URL phishing detector. Paste a suspicious link and get a safety
verdict (**Safe / Suspicious / High Risk**) based on rule-based red flags.

> **Pure static analysis.** Ziva treats the URL as a string only. It never fetches,
> visits, or resolves the submitted link.

## Features
- 14 rule-based checks with weights and plain-English explanations
- 0–100 risk score, animated gauge, color-coded verdict
- URL anatomy breakdown (scheme, subdomain, domain, TLD, path)
- Defanged URL display (`hxxps://evil[.]com`), never rendered as a clickable link
- Last 10 checks saved in the browser (localStorage), light/dark mode
- Rate limiting (30 requests/min per IP), input validation, XSS-safe rendering

## Tech stack
Python 3.11+, FastAPI, Pydantic, vanilla HTML/CSS/JS, pytest.
The detection engine uses only the standard library (`urllib.parse`, `re`, `ipaddress`).

## Quick start
```bash
git clone https://github.com/<your-username>/ziva.git
cd ziva
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000 — API docs at http://127.0.0.1:8000/api/docs

## Run tests
```bash
pytest
```

## Project structure
```
ziva/
├── app/
│   ├── main.py        # API routes, rate limiting, static serving
│   ├── analyzer.py    # detection logic (pure functions, no I/O)
│   ├── rules.py       # weights, thresholds, keyword/brand lists
│   └── schemas.py     # Pydantic models
├── static/            # index.html, style.css, script.js
├── tests/test_analyzer.py
├── requirements.txt
└── README.md
```

## API
`POST /api/analyze`
```json
{ "url": "https://google.com@evil.com" }
```
Returns `url`, `normalized_url`, `defanged_url`, `score`, `verdict`, `findings[]`, and `parsed{}`.

`GET /api/health` returns app status.

Invalid input (empty, over 2048 characters, no hostname) returns `422`.

## Scoring
Triggered rule weights are summed and capped at 100.

| Score | Verdict    |
|-------|------------|
| 0–24  | Safe       |
| 25–59 | Suspicious |
| 60+   | High Risk  |

All weights and thresholds live in `app/rules.py`.

## Rules
| # | Rule | Severity |
|---|------|----------|
| 1 | IP address instead of domain (incl. hex/decimal/IPv6) | High |
| 2 | Missing HTTPS | Medium |
| 3 | `@` symbol (browser ignores text before it) | High |
| 4 | 3+ hyphens in hostname | Medium |
| 5 | URL over 75 chars or hostname over 30 | Low |
| 6 | 3+ subdomain levels | Medium |
| 7 | Brand impersonation (brand in URL, wrong registered domain) | High |
| 8 | Suspicious keywords (login, verify, secure…), capped | Low |
| 9 | High-risk TLD (.xyz, .top, .tk, .zip…) | Medium |
| 10 | Punycode / non-ASCII homograph | High |
| 11 | URL shortener | Medium |
| 12 | Non-standard port | Low |
| 13 | Many `%xx` / special characters in path | Low |
| 14 | Double slash or embedded redirect | Low |

## Limitations
"Safe" means **no red flags found**, not a guarantee. Rule-based detection cannot catch
brand-new phishing domains with clean-looking names, compromised legitimate websites, or
content-based phishing (fake pages on trusted hosts). Ziva is an educational tool, not a
replacement for real security software.

## License
MIT
