# API Testing Methodology (redagent web-tester playbook)

A checklist for testing REST/JSON APIs, complementing web_methodology.md. Based
on the OWASP API Security Top 10 (2023). Scope is enforced by the scope guard —
only configured/authorized targets run. Test with the agent's tools
(fetch_url / http_request / sql_test / vuln_scan); never hand-type payloads into
sql_test/xss_test — those tools inject their own.

## Order of work (one tool per turn)
1. **Map the API** — fetch_url on the API root (`/api`, `/rest`, `/v1`,
   `/graphql`). Record discovered resources and whether responses are JSON.
2. **Read responses** — note the data shape, object IDs, tokens, and any field
   that looks like it references another user's object.
3. **Probe each parameterized endpoint by class** (see checklist below).
4. **Verify & report** — one finding per confirmed issue, with the exact
   endpoint, the request that proves it, impact, and remediation.

## Coverage checklist (OWASP API Top 10 mapping)
- [ ] API1 Broken Object Level Auth (BOLA/IDOR): with http_request, request an
      object by an ID that should belong to another user; a 200 with their data
      is the finding. Vary only the ID.
- [ ] API2 Broken Authentication: unauthenticated access to endpoints that
      should require a token; weak/missing auth on `/token`, `/login`.
- [ ] API3 Broken Object Property Level Auth: responses that return more fields
      than the caller should see (mass-assignment / excessive data exposure).
- [ ] API5 Broken Function Level Auth: a normal user reaching admin-only routes
      (`/admin`, `/users`, DELETE/PUT methods).
- [ ] API8 Security Misconfiguration: missing security headers, verbose errors,
      permissive CORS (fetch_url headers, vuln_scan).
- [ ] Injection into API parameters: sql_test on JSON/query params (clean value).

## Method notes
- APIs often ignore the method: try GET where the UI uses POST, and vice versa,
  with http_request.
- Auth is usually a Bearer token or cookie — capture it from a normal response,
  then reuse/vary it with http_request to test access control.
- Prefer real endpoints from recon over guessed ones.

## Concrete tool calls (copy these shapes)
- **Read an API resource** — fetch_url with the full URL:
  - GOOD: `fetch_url(url="http://localhost:3001/api/Users")`
- **IDOR / BOLA** — http_request the same endpoint varying ONLY the id. A 200
  returning another user's object is the finding:
  - `http_request(method="GET", url="http://localhost:3001/rest/basket/1")`
  - `http_request(method="GET", url="http://localhost:3001/rest/basket/2")`
  - compare: does basket 2 return data while logged in as user 1? → BOLA.
- **Method tampering** — try a method the UI doesn't use:
  - `http_request(method="GET",  url="http://localhost:3001/api/Products/1")`
  - `http_request(method="PUT",  url="http://localhost:3001/api/Products/1", body="{...}")`
    (does a normal user edit a product? → broken function-level auth)
- **Auth with a captured token** — reuse/vary the Bearer token from a login
  response to reach a gated route:
  - `http_request(method="GET", url="http://localhost:3001/rest/user/whoami",
    headers="{\"Authorization\": \"Bearer <token from login>\"}")`
- **Injection into an API param** — CLEAN value, sql_test injects its own:
  - GOOD: `sql_test(url="http://localhost:3001/rest/products/search?q=apple")`
  - BAD:  typing SQL into q= yourself (sqlmap rejects tainted input)

## This lab's API hotspots (Juice Shop)
- `GET /api/Users/{id}` — BOLA: read another user's record
- `GET /rest/basket/{id}` — BOLA: read another user's basket
- `POST /rest/user/login` — broken auth: the email field is SQL-injectable
- `GET /api/Products/{id}` + PUT/DELETE — function-level auth: can a normal user write?
- `GET /rest/products/{id}/reviews` — NoSQL injection
- `GET /api/Feedbacks` — excessive data exposure (returns all feedback)

## What needs a human
- Multi-step business-logic abuse (coupon stacking, price tampering sequences)
- Chained auth flows (refresh-token replay, OAuth state handling)
- Rate-limit / resource-consumption testing (API4) — avoid on shared targets

## Reference sources
- OWASP API Security Top 10 (2023) — the classes behind this checklist
- OWASP WSTG — API test cases
- PortSwigger Web Security Academy — API testing labs
