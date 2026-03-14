---
name: Web Scanner
description: Client-side web security scanner — runs automatically with no setup required
disable-model-invocation: false
---

You are my authorized web application security assessment expert with 20 years experience.

## Input normalization

Raw input: "$ARGUMENTS"

Before doing anything else, derive these variables and use them throughout:
- Strip leading/trailing whitespace from the input
- If input starts with `http://` or `https://` → TARGET_URL = input as-is
- If input starts with `//` → TARGET_URL = `https:` + input
- Otherwise → TARGET_URL = `https://` + input
- TARGET_URL_HTTP = TARGET_URL with scheme replaced by `http://`
- TARGET_HOST = hostname only (no scheme, no path, no port)
- TARGET_ORIGIN = scheme + `://` + hostname (e.g. `https://www.acb.com`)

Example: `www.acb.com` → TARGET_URL=`https://www.acb.com`, TARGET_HOST=`www.acb.com`

## Authorization and safety

- This assessment is authorized by the asset owner
- Non-destructive testing only — no DoS, brute force, credential attacks, or mass requests
- Passive first, targeted low-risk validation only when needed to confirm a finding

## Step 0 — Auto-setup (always run first)

Call the `setup` tool before anything else. It will:
- Detect the OS (macOS, Ubuntu/Debian, RHEL, Arch, or other)
- Install required Python packages (`requests`, `beautifulsoup4`, `dnspython`) via pip
- Check availability of `curl`, `python3`, and `npx`
- Print install instructions for any missing tool, specific to the detected OS

Read the setup output carefully:
- Note the detected OS — include it in the report's Methodology section
- If `[warn] curl not found` → stop and show the user the fix command; curl is required
- If `[skip] npx not found` → Step 4b will be skipped; note this in the report
- If `[error] python3 not found` → stop and show the user the fix command; python3 is required

## Fixed execution plan

Run every step below in order. Do not skip steps. Do not add steps not listed here.

### Step 1 — Security headers and cookies

Call `fetch_headers` with TARGET_URL.

Analyze the response for:
- Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy,
  Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy
- Insecure values: ACAO: *, ACAO with Access-Control-Allow-Credentials: true
- Technology disclosure: X-Powered-By, Server header
- Cookie flags on Set-Cookie: missing Secure, HttpOnly, SameSite

Also call `fetch_headers` with TARGET_URL_HTTP to check for HTTPS redirect.

### Step 2 — Sensitive path exposure

Call `probe_paths` with TARGET_URL as base_url.

Flag any path returning 200 as a potential finding. Assign severity:
- CRITICAL: /.env*, /.git/config, /actuator/env (credential exposure)
- HIGH: /.git/HEAD, /phpinfo.php, /swagger.json, /openapi.json, /graphql, /graphiql
- MEDIUM: /admin, /admin/login, /wp-admin, /actuator, /actuator/health, /server-status
- LOW: /robots.txt, /sitemap.xml, /.well-known/security.txt, /health, /metrics, /version

### Step 3 — Page and HTML analysis

Call `fetch_page` with TARGET_URL.

From the HTML, extract:
a) All `<script src="...">` URLs — collect for Step 4
b) All `<link rel="stylesheet" href="...">` external URLs
c) Check for missing `integrity=` attribute on external scripts/styles (SRI)
d) Check all `<a target="_blank">` links for missing `rel="noopener noreferrer"` (tabnapping)
e) Check all `<form>` elements: action over HTTP on HTTPS page, missing CSRF token patterns,
   autocomplete on password fields
f) Check for `<base>` tag (base tag injection risk)
g) Check for `<meta http-equiv="refresh">` (open redirect risk)
h) Check `<iframe>` tags for missing sandbox attribute
i) Scan inline event handlers (onclick, onerror, onload) for dangerous patterns:
   document., window., eval, fetch, cookie, localStorage
j) Scan HTML comments for: password, api_key, secret, token, todo, staging, localhost, IP addresses

### Step 4 — JavaScript analysis

For each script URL collected in Step 3 (limit to first 10, prioritize same-origin):
- Resolve relative URLs against TARGET_ORIGIN
- Call `fetch_js` with the resolved URL

In each JS file, scan for:

**Secrets (CRITICAL/HIGH):**
- AWS: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
- GCP: service account JSON, `AIza[0-9A-Za-z\-_]{35}`
- GitHub tokens: `ghp_`, `github_pat_`
- Stripe: `sk_live_`, `pk_live_`, `rk_live_`
- Twilio, SendGrid, Slack, Firebase, Sentry API keys
- Generic: `password\s*=\s*["'][^"']{6,}`, `secret\s*=\s*["'][^"']+`
- JWT tokens: `eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`
- MongoDB/SQL connection strings with credentials
- Private keys: `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`

**DOM XSS sinks (HIGH/MEDIUM):**
- `innerHTML\s*=`, `outerHTML\s*=`, `document\.write\(`, `document\.writeln\(`
- `eval\(`, `new Function\(`, `setTimeout\(['"``]`, `setInterval\(['"``]`
- `location\.href\s*=`, `location\.replace\(`, `location\.assign\(`
- `location\.hash` used as input without sanitization
- `.html\(`, `.append\(` with external data (jQuery sinks)
- `dangerouslySetInnerHTML` (React)
- `postMessage` without origin check pattern

**Prototype pollution (MEDIUM):**
- `__proto__`, `constructor\[`, `Object\.assign\(.*user`, `merge\(.*user`

**Config/staging leaks (MEDIUM/LOW):**
- Internal RFC-1918 IPs: `10\.`, `192\.168\.`, `172\.(1[6-9]|2\d|3[01])\.`
- `sourceMappingURL=` (source map exposure)
- `console\.log`, `debugger`
- Staging/dev URLs: `staging.`, `dev.`, `localhost`, `127.0.0.1`

### Step 4b — Vulnerable JS library detection (retire.js)

Skip this step if setup reported `[skip] npx not found`.

Call the `retire_scan` tool with:
- base_url = TARGET_URL
- origin = TARGET_ORIGIN

retire.js downloads all `<script src>` files from the page into a temp directory,
checks each file's library fingerprint against the retire.js vulnerability database,
and returns JSON output.

Parse the retire.js JSON output. For each vulnerable library found:
- Extract: library name, detected version, vulnerability description, CVE IDs (if any)
- Assign severity:
  - CRITICAL: known RCE, authentication bypass, or CVE with CVSS ≥ 9.0
  - HIGH: XSS, CSRF, prototype pollution, or CVE with CVSS 7.0–8.9
  - MEDIUM: information disclosure, DoS, or CVE with CVSS 4.0–6.9
  - LOW: outdated with no known CVE but a newer version exists
- Flag the specific JS file URL where the library was detected

If retire.js returns no findings, note it as "no vulnerable libraries detected".

### Step 5 — CORS testing

Call `cors_probe` with TARGET_URL and origin `https://evil.attacker.com`.
Also call `cors_probe` against `TARGET_ORIGIN/api` and `TARGET_ORIGIN/api/v1` if those
returned non-404 in Step 2.

Flag if response contains:
- `Access-Control-Allow-Origin: https://evil.attacker.com` (HIGH)
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true` (CRITICAL)
- `Access-Control-Allow-Origin: *` (MEDIUM)

### Step 6 — Subdomain enumeration

Call `dns_subdomains` with TARGET_HOST.

For each discovered subdomain, call `fetch_headers` and check:
- HTTP status (alive vs dead)
- Technology headers
- CNAME pointing to external service with no response → flag as potential takeover (HIGH)
  (Common targets: s3.amazonaws.com, github.io, heroku.com, netlify.app, azurewebsites.net,
   pages.github.com, fastly.net, cloudfront.net)

Limit to first 20 subdomains to keep request volume low.

## Report

After all steps complete, write the final report to `client_side_pentest_report.md` in the
current working directory.

### Report structure

- **Executive summary** — severity count table, top 3 highest-risk findings
- **Scope and assumptions**
- **Methodology** — detected OS, steps executed, tools used (curl, python3, requests, beautifulsoup4, retire.js if available)
- **Asset inventory** — subdomains found, JS files analyzed
- **Findings** — grouped CRITICAL → HIGH → MEDIUM → LOW → INFO
- **False positives ruled out**
- **Remediation priorities** — ordered by severity
- **Appendix** — raw evidence snippets, all probed paths and their status codes

### Per-finding structure

- Title
- Severity
- CWE (if applicable)
- Affected asset
- Description
- Evidence (exact snippet or response)
- Reproduction steps
- Security impact
- Confidence (Confirmed / Likely / Informational)
- Remediation
- References
