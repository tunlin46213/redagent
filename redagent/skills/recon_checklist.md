# Recon Checklist (redagent recon playbook)

A systematic enumeration checklist the recon agent follows so it hands the web
tester a complete map instead of a half-scanned host. Scope is enforced by the
scope guard — only configured/authorized targets run. Recon does NOT test
vulnerabilities; it discovers and describes.

## Order of work (one tool per turn)
1. **Port/service sweep** — `nmap_web_scan` on the target. Record every open web
   port, the service/version banner, and anything non-standard (8080, 3000,
   8443, management ports).
2. **Endpoint discovery** — `dir_bruteforce` on each live web service. Record
   every discovered path with its status code.
3. **Describe & hand off** — summarize in a few lines, then name exactly what the
   web tester should probe (which endpoints look parameterized or sensitive).

## What to flag for the web tester
- Parameterized endpoints (`?q=`, `?id=`, `/search`, `/rest/...`) → candidates
  for sql_test / xss_test.
- API roots (`/api`, `/rest`, `/graphql`, `/v1`) → candidates for api_testing.
- Auth surfaces (`/login`, `/admin`, `/account`, `/token`) → access-control notes.
- Exposed/sensitive paths (`/ftp`, `/metrics`, `/.git`, `/backup`, `/debug`) →
  sensitive-data-exposure candidates.
- Interesting status codes: 401/403 (auth-gated, worth revisiting), 500 (error
  leakage), 301/302 (redirects to new hosts — stay in scope).

## Coverage checklist
- [ ] All open web ports enumerated (nmap_web_scan)
- [ ] Endpoints discovered on each service (dir_bruteforce)
- [ ] Tech/version banners recorded
- [ ] Candidates classified (parameterized / API / auth / exposure)
- [ ] Handoff names concrete endpoints, not "scan everything"

## Concrete tool calls + a good handoff (copy these shapes)
- **Port sweep** — host only, no scheme/path:
  - GOOD: `nmap_web_scan(target="localhost")`
- **Endpoint discovery** — against a live web service:
  - GOOD: `dir_bruteforce(url="http://localhost:3001/")`
- **A good handoff names endpoints and classes, not "scan everything":**
  > "web services: 3001 (Node/Express, Juice Shop). Endpoints found: /rest/products/search
  > (parameterized → SQLi/XSS candidate), /api/Users and /rest/basket/{id} (object access →
  > IDOR candidates), /ftp (directory listing → sensitive exposure), /metrics (Prometheus →
  > exposure). web tester: start with sql_test on /rest/products/search?q=, then IDOR on
  > /rest/basket/{id}, then fetch_url /ftp and /metrics."
- **A bad handoff:** "found the site, test it for vulnerabilities." (no leads → the
  7B web tester guesses paths and misses the real endpoints)

## Boundaries
- Do not run sql_test / xss_test / vuln_scan yourself — that is the web tester.
- Do not pivot to hosts not in scope, even if recon reveals links to them.
- A discovered path is not a finding; it is a lead. Report leads, not verdicts.
