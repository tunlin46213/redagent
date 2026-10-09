# Web App Testing Methodology (redagent operator playbook)

A systematic checklist the agent follows so it tests thoroughly instead of firing
tools at random. Based on the OWASP Web Security Testing Guide (WSTG). Scope is
enforced by the scope guard — only configured/authorized targets run.

## Order of work
1. **Map** — nmap_web_scan (open web ports/services), dir_bruteforce (endpoints).
   Note every endpoint, its status code, and anything unusual (/ftp, /metrics,
   /api, admin, 401/500 responses).
2. **Inspect** — for each interesting endpoint, fetch_url to read headers + body.
   Record: server/tech, missing security headers (CSP, HSTS, X-Frame-Options),
   exposed data.
3. **Test each endpoint by vuln class** (one tool per turn):
   - Parameterized URL/API → `sql_test` (clean param value, e.g. q=apple)
   - Reflecting/parameterized page → `xss_test`
   - Whole app → `vuln_scan` (nuclei: CVEs, misconfig, exposures)
4. **Verify** — confirm each tool finding is real (re-read evidence); drop tool
   warnings/noise. A warning is not a vulnerability.
5. **Report** — one finding per real issue, with Severity / Affected endpoint /
   Evidence (the payload or response) / Impact / Remediation.

## Coverage checklist (WSTG mapping)
- [ ] Information gathering: ports, endpoints, tech, headers (nmap, dir_bruteforce, fetch_url)
- [ ] Injection: SQLi (sql_test), command/template (vuln_scan templates)
- [ ] XSS: reflected/stored (xss_test) — note DOM XSS needs a browser, not covered
- [ ] Security misconfiguration & exposures (vuln_scan, fetch_url headers)
- [ ] Sensitive data exposure: readable files/dirs, /metrics, /ftp (fetch_url)
- [ ] Known vulnerable components / CVEs (vuln_scan)

## What this playbook does NOT automate (needs a human)
- Broken access control / IDOR (test with http_request varying IDs/tokens)
- Authentication & session logic flaws
- Business-logic abuse
- DOM-based XSS (client-rendered; needs a headless browser)

## Concrete tool calls (copy these shapes)
Good vs bad for each step — the shape matters more than the host.

- **Inspect headers** — fetch_url with a full URL:
  - GOOD: `fetch_url(url="http://localhost:3001/")`
  - BAD:  `fetch_url(url="localhost")` (no scheme) · `fetch_url(url="/")` (bare path)
- **SQLi on a parameterized endpoint** — pass a CLEAN value; sql_test injects:
  - GOOD: `sql_test(url="http://localhost:3001/rest/products/search?q=apple")`
  - BAD:  `sql_test(url=".../search?q=apple' OR '1'='1")` (hand-typed → sqlmap
    rejects it as tainted and finds nothing)
- **XSS on a reflecting param** — clean value, tool injects:
  - GOOD: `xss_test(url="http://localhost:3001/rest/products/search?q=apple")`
  - NOTE: the Angular route `/#/search?q=` is DOM XSS — xss_test (HTTP-level)
    can't see it; don't report its absence as "no XSS", say it needs a browser.
- **Whole-app CVE/misconfig sweep**:
  - GOOD: `vuln_scan(url="http://localhost:3001/")`
- **Sensitive exposure** — fetch the path and read the body:
  - GOOD: `fetch_url(url="http://localhost:3001/ftp")` (directory listing?)
  - GOOD: `fetch_url(url="http://localhost:3001/metrics")` (Prometheus leak?)

## This lab's known hotspots (Juice Shop)
Use these real endpoints instead of guessing (`/search`, `/api/login`):
- `GET /rest/products/search?q=` — JSON REST, SQLi lives here (sql_test)
- `POST /rest/user/login` — auth; email field is injectable (see api_testing.md)
- `GET /api/Users`, `GET /api/BasketItems`, `GET /rest/basket/{id}` — object access
  (IDOR candidates — vary the id with http_request, see api_testing.md)
- `GET /ftp` — directory listing with sensitive files
- `GET /metrics` — Prometheus metrics exposure
- `GET /rest/products/{id}/reviews` — NoSQL injection candidate
- `/#/search?q=` — DOM XSS (client-rendered; needs a headless browser, not xss_test)

## Reference sources (technique depth)
- OWASP WSTG — the test cases behind this checklist
- PortSwigger Web Security Academy — per-class hands-on theory
- OWASP Juice Shop companion book — for this lab's challenges
