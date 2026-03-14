# webscanner

A [Claude Code](https://claude.ai/code) plugin that performs automated client-side web security assessments. Point it at any domain and it produces a structured Markdown pentest report covering secrets exposure, vulnerable JS libraries, security misconfigurations, XSS sinks, CORS issues, and more — with zero manual setup required.

## What it does

**webscanner** runs a fixed 6-step security review against the target's browser-facing attack surface:

| Step | Check | Tools used |
|------|-------|------------|
| 0 | OS detection + auto-install deps | `pip3`, `uname` |
| 1 | Security headers, cookie flags, HTTPS redirect | `curl` |
| 2 | Sensitive path exposure (`.env`, `.git`, Swagger, admin panels, etc.) | `curl` |
| 3 | HTML analysis — SRI, tabnapping, CSRF, clickjacking, base tag injection, HTML comment secrets | `curl` |
| 4 | JavaScript analysis — 40+ secret patterns, DOM XSS sinks, prototype pollution, source map exposure | `curl`, `python3` |
| 4b | Vulnerable JS library detection via retire.js CVE database | `npx retire` *(requires Node.js)* |
| 5 | CORS misconfiguration testing | `curl` |
| 6 | Subdomain enumeration + takeover detection via crt.sh | `curl`, `python3` |

### What it detects

**Secrets & sensitive data**
- AWS / GCP / GitHub / Stripe / Twilio / SendGrid / Slack / Firebase / Sentry API keys
- JWT tokens, private keys, hardcoded passwords, database connection strings
- Internal IPs, staging URLs, source maps, debug artifacts in production JS

**Vulnerabilities**
- DOM XSS sinks: `innerHTML`, `document.write`, `eval`, `location.href`, `dangerouslySetInnerHTML`
- Prototype pollution patterns
- Missing / misconfigured security headers (CSP, HSTS, X-Frame-Options, CORP, COOP, etc.)
- Insecure cookie flags (missing `Secure`, `HttpOnly`, `SameSite`)
- CORS misconfiguration (wildcard, origin reflection, credentials + wildcard)
- Subdomain takeover (S3, GitHub Pages, Heroku, Netlify, Azure, Fastly, Cloudfront)
- Exposed sensitive paths: `.env`, `.git/config`, `/actuator/env`, Swagger, GraphQL, phpinfo

**Library vulnerabilities**
- Known CVEs in jQuery, Bootstrap, lodash, Angular, React, and 1000+ other libraries via the retire.js database

---

## Requirements

| Dependency | Required | Notes |
|------------|----------|-------|
| `python3` | Yes | 3.7+ |
| `curl` | Yes | Pre-installed on macOS and most Linux |
| `pip3` | Yes | Ships with Python 3 |
| `npx` / Node.js | No | Enables Step 4b (retire.js). Without it, library CVE scanning is skipped. |

The plugin **auto-installs** `requests`, `beautifulsoup4`, and `dnspython` on first run via `pip3 install --user`. If anything is missing it prints the correct install command for your OS (macOS, Ubuntu/Debian, RHEL, Arch).

---

## Installation

**Option A — Load directly (no install, development/personal use):**
```bash
claude --plugin-dir /path/to/web_scan
```

**Option B — Install from GitHub (persistent, recommended):**
```
/plugin marketplace add enderphan94/web_scan
/plugin install webscan@enderphan94
```

---

## Usage

```
/webscan:scan <target>
```

The target can be in any of these formats — the plugin normalises it automatically:

```
/webscan:scan acb.com
/webscan:scan www.acb.com
/webscan:scan https://www.acb.com
/webscan:scan http://staging.acb.com/app
```

The scan runs all steps and writes a report to `client_side_pentest_report.md` in your current working directory.

---

## Example use cases

**Bug bounty recon**
```
/webscan:scan target.com
```
Quickly maps the client-side attack surface before manual testing — surfaces exposed secrets, vulnerable libraries, and misconfigured headers in one pass.

**Pre-release security review**
```
/webscan:scan staging.myapp.com
```
Catch hardcoded API keys, missing security headers, and vulnerable dependencies before shipping to production.

**CTF / web challenge**
```
/webscan:scan chall.ctf.example.com
```
Automates the initial recon phase — checks for exposed `.git`, source maps, debug endpoints, and JS secrets that are common CTF entry points.

**Third-party vendor assessment**
```
/webscan:scan vendor-portal.thirdparty.com
```
Assess the client-side security posture of a vendor's web portal without needing access to their source code.

**Internal audit**
```
/webscan:scan https://intranet.company.internal
```
Audit internal web apps for the same issues that external attackers would look for.

---

## Output

The plugin writes `client_side_pentest_report.md` with:

- **Executive summary** — severity count table and top 3 findings
- **Methodology** — OS detected, steps run, tools used
- **Asset inventory** — subdomains and JS files found
- **Findings** — grouped CRITICAL → HIGH → MEDIUM → LOW → INFO, each with evidence, reproduction steps, impact, and remediation
- **False positives** — explicitly called out
- **Remediation priorities** — ordered by severity
- **Appendix** — raw evidence, all probed paths and HTTP status codes

---

## Approximate token usage

Token usage depends on the target's JS bundle size and number of findings. Typical ranges:

| Target type | Input tokens | Output tokens | Total |
|-------------|-------------|---------------|-------|
| Simple landing page (1–3 JS files) | ~8,000–15,000 | ~3,000–5,000 | ~11,000–20,000 |
| Medium SPA (5–10 JS files) | ~20,000–45,000 | ~5,000–10,000 | ~25,000–55,000 |
| Large app (10+ JS files, many subdomains) | ~50,000–120,000 | ~8,000–20,000 | ~58,000–140,000 |

**What drives token usage:**
- JS file sizes — minified bundles are large. The plugin caps analysis at 10 JS files.
- Number of subdomains returned by crt.sh — capped at 20 probes.
- Number of findings — more findings = longer report = more output tokens.

> Tip: If you are on a token budget, run against a specific path (`/webscan:scan example.com/app`) rather than the root to limit the HTML and JS surface crawled.

---

## Safety and scope

- **Non-destructive only** — no brute force, no credential stuffing, no DoS
- **Passive first** — reads publicly accessible pages and JS; does not attempt to exploit
- **Moderate request volume** — respects rate limits; paths are probed once, not in loops
- **Authorized use only** — only scan targets you own or have explicit written permission to test

---

## License

MIT — see [LICENSE](LICENSE)

## Author

[Ender Phan](https://github.com/enderphan94)
