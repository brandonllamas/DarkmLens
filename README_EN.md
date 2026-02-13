# DarkmLens v4.2 (Darkmoon)

**DarkmLens** is a **defensive, passive analysis** tool that generates a **public exposure report** for a web application you own or for which you have **explicit authorization** (audit, authorized pentest, internal validation, etc.).

It can:
- Detect technologies (optional via Wappalyzer).
- Discover internal routes (DOM + heuristics over JS/CSS + JS navigation extraction).
- Infer requests to endpoints (fetch/axios) and extract hints for **HTTP methods**, **query params**, and **possible body keys**.
- Identify backend/config hints (headers, cookies, CloudFront, Firebase, Cognito, Sentry, etc.).
- Crawl same-origin pages (optional).
- Take screenshots with Playwright (optional).
- Run an “AuthZ Audit” (visit discovered routes and classify **with access / no access**).
- Generate a polished **HTML report** plus a complete `results.json`.

---

## ⚠️ Responsible use (mandatory)

Use this project **only** on:
- Assets that belong to you or your organization, or
- Systems where you have **explicit written permission** to test.

Do **not** use this tool to:
- Scan third-party sites without authorization.
- Bypass authentication, evade controls, or exploit vulnerabilities.
- Collect or exfiltrate sensitive data.

**The author/end user is responsible for lawful use and compliance with internal policies and written authorization.**

---

## Requirements

- Python **3.10+** recommended (works on 3.11 / 3.12 too).
- `pip` enabled.
- **Pipenv** (recommended workflow).
- Optional: `playwright` for screenshots.
- Optional: a Python Wappalyzer library that provides `from Wappalyzer import Wappalyzer, WebPage`.
- Optional: `ollama` installed locally if you want per-route AI summaries.

---

## Install Pipenv

### Windows (PowerShell or CMD)

1) Verify Python:
```bash
py --version
py -m pip --version
```

2) Install Pipenv:
```bash
py -m pip install --user pipenv
```

3) If `pipenv` is not found, add the Python Scripts directory to PATH (commonly):
- `C:\Users\<YOUR_USER>\AppData\Roaming\Python\Python3x\Scripts\`

Open a new terminal and verify:
```bash
pipenv --version
```

---

### macOS

Option A (recommended): Homebrew
```bash
brew install pipenv
pipenv --version
```

Option B (pip)
```bash
python3 -m pip install --user pipenv
pipenv --version
```

---

### Linux

Option A (pip)
```bash
python3 -m pip install --user pipenv
pipenv --version
```

If `pipenv` is not recognized, add `~/.local/bin` to PATH:
```bash
export PATH="$HOME/.local/bin:$PATH"
```
(ideally add it to `~/.bashrc` or `~/.zshrc`)

---

## Project installation

From the project folder (where `app.py` is located):

1) Create the environment and install dependencies:
```bash
pipenv install
```

2) Optional extras:

**Playwright** (screenshots):
```bash
pipenv install playwright
pipenv run playwright install chromium
```

**Wappalyzer** (technology detection):
```bash
pipenv install python-Wappalyzer
```

> Note: the package name may vary depending on the library you use. Install the one that exposes `Wappalyzer` and `WebPage` as in your code.

---

## How to run

Minimal example:
```bash
pipenv run python app.py https://example.com --out out/example
```

---

## Main CLI options

- `--out out/folder`  
  Output folder.

- `--max-assets 120`  
  Max same-origin assets (JS/CSS) to download/analyze.

- `--max-maps 20`  
  Max sourcemaps to download (if detected).

- `--timeout 15`  
  Request timeout in seconds.

- `--sleep 0.03`  
  Pause between requests (helps reduce load / rate-limits).

- `--no-screenshot`  
  Disable screenshots (does not require Playwright).

- `--no-crawl`  
  Disable same-origin crawling.

- `--max-pages 25` and `--max-depth 2`  
  Crawling limits.

- `--no-save-bodies`  
  Do not save per-route response bodies to `routes/*.txt`.

- `--probe-get`  
  “Safe-ish” probe of some inferred same-origin GET endpoints to capture status/CT.

---

## Authenticated crawling via headers (optional)

Pass headers directly (repeatable):
```bash
pipenv run python app.py https://myapp.com   --header "Cookie: session=XXXX"   --header "X-Token: ABC"   --out out/myapp
```

Or from a JSON file:
```bash
pipenv run python app.py https://myapp.com --headers-json headers.json --out out/myapp
```

Or bearer token convenience:
```bash
pipenv run python app.py https://myapp.com --bearer "YOUR_TOKEN" --out out/myapp
```

---

## AuthZ Audit (classifies routes “with access / no access”)

Enable route auditing:
```bash
pipenv run python app.py https://myapp.com --audit-authz --out out/myapp
```

Limit number of routes:
```bash
pipenv run python app.py https://myapp.com --audit-authz --authz-max-routes 200 --out out/myapp
```

Alias (same as `--authz-max-routes`):
```bash
pipenv run python app.py https://myapp.com --audit-authz --audit-authz-limit 200 --out out/myapp
```

Disable screenshots during AuthZ audit (still visits routes):
```bash
pipenv run python app.py https://myapp.com --audit-authz --authz-no-screenshot-all --out out/myapp
```

Include a response snippet (use with care):
```bash
pipenv run python app.py https://myapp.com --audit-authz --authz-show-response --authz-response-chars 900 --out out/myapp
```

---

## Probe GET (safe-ish)

Probe a subset of inferred same-origin endpoints with **GET** to capture status/content-type:
```bash
pipenv run python app.py https://myapp.com --probe-get --out out/myapp
```

> Note: this performs additional requests. Use only with authorization and reasonable limits.

---

## Local AI summaries (Ollama)

If you have `ollama` installed and want short per-route summaries (AuthZ audit):
```bash
pipenv run python app.py https://myapp.com --audit-authz --ai-ollama --ai-model llama3.1:8b --out out/myapp
```

If `ollama` is not available, the tool falls back to a heuristic summary (never blank).

---

## Output files

Inside `--out`:
- `index.html` → visual report (dashboard).
- `results.json` → full raw results.
- `report.template.html` → editable HTML template used to render the report.
- `routes/*.txt` → saved route bodies (unless `--no-save-bodies`).
- `screens/*.png` → screenshots (if Playwright is installed and screenshots are enabled).

---

## Security & privacy notes

- If you pass session headers/cookies, they may affect requests. **Do not share reports publicly** if they may contain sensitive information.
- `routes/*.txt` can include HTML/JSON with internal data depending on the target.
- Use `--no-save-bodies` if you don’t want to persist route contents.

---

## Troubleshooting

**1) “Playwright not installed: no screenshots.”**  
Install Playwright and the Chromium browser:
```bash
pipenv install playwright
pipenv run playwright install chromium
```

**2) “Wappalyzer not installed (optional).”**  
Install the dependency you chose:
```bash
pipenv install python-Wappalyzer
```

**3) SSL / corporate TLS inspection issues**  
In proxy/TLS inspection environments, you may need to configure system certificates or environment variables (depends on the setup).

---

## License / Authorship

DarkmLens v4.2 — Darkmoon  
Defensive and authorized use only.
