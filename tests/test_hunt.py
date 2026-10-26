"""Worklist engine: lead seeding, finding detection, and the chaining hooks."""

from redagent import hunt
from redagent.hunt import Lead, Finding


DIRB = """rest/products/search (Status: 200) [Size: 16563]
ftp                  (Status: 200) [Size: 11307]
metrics              (Status: 200) [Size: 26000]
rest/user/login      (Status: 500)"""


def test_base_normalises():
    assert hunt._base("localhost:3001") == "http://localhost:3001"
    assert hunt._base("http://h:3001/x") == "http://h:3001"


def test_seed_leads_classes_and_severity_order():
    leads = hunt.seed_leads("http://localhost:3001", DIRB)
    classes = {l.vuln_class for l in leads}
    assert {"sqli", "xss", "exposure", "misconfig"} <= classes
    # severity-ordered: no 'medium' lead appears before a 'high' lead
    sev = [hunt.SEVERITY[l.severity] for l in leads]
    assert sev == sorted(sev)
    # the SQLi lead targets the real search endpoint with a clean param
    sqli = [l for l in leads if l.vuln_class == "sqli"][0]
    assert sqli.url.endswith("/rest/products/search?q=apple")


def test_seed_leads_from_crawl_params():
    crawl = "\n".join([
        "http://localhost:3001/rest/products/search?q=foo",   # param -> sqli+xss
        "http://localhost:3001/rest/products/search?q=bar",   # same sig -> deduped
        "http://localhost:3001/api/items?id=5&cat=x",         # distinct endpoint
        "http://localhost:3001/about",                        # no param -> ignored
        "http://evil.example/x?p=1",                          # off-host -> ignored
    ])
    leads = hunt.seed_leads("http://localhost:3001", "", crawl)
    crawled = [l for l in leads if "crawled" in l.reason]
    sqli = {l.url for l in crawled if l.vuln_class == "sqli"}
    # one sqli lead per endpoint signature (the two ?q= URLs collapse to one)
    assert sqli == {"http://localhost:3001/rest/products/search?q=foo",
                    "http://localhost:3001/api/items?id=5&cat=x"}
    # each crawled param endpoint seeds BOTH sqli and xss
    assert {l.vuln_class for l in crawled} == {"sqli", "xss"}
    # off-host and param-less URLs never become leads
    assert not any("evil.example" in l.url or l.url.endswith("/about") for l in leads)


def test_is_finding_sql_test():
    hit, sev, _ = hunt._is_finding(
        Lead("u", "sqli", "sql_test", ""),
        "GET parameter 'q' is vulnerable.\nParameter: q (GET)")
    assert hit and sev == "critical"


def test_is_finding_vuln_scan_and_nikto():
    assert hunt._is_finding(Lead("u", "misconfig", "vuln_scan", ""),
                            "[prometheus-metrics] [http] [medium] u")[0]
    assert hunt._is_finding(Lead("u", "misconfig", "nikto_scan", ""),
                            "+ Server leaks via ETag")[0]


def test_is_finding_downloadable_file_but_not_robots():
    assert hunt._is_finding(Lead("http://h/ftp/x.bak", "exposure", "fetch_url", "", "high"),
                            "HTTP 200\n\n<data>")[0]
    # robots.txt is informational, not a real exposure
    assert not hunt._is_finding(Lead("http://h/robots.txt", "exposure", "fetch_url", "", "high"),
                                "HTTP 200\n\nUser-agent: *")[0]
    # 403 (blocked .bak) is not a finding
    assert not hunt._is_finding(Lead("http://h/ftp/x.bak", "exposure", "fetch_url", "", "high"),
                                "HTTP 403\n\nforbidden")[0]


def test_exposure_labels_content_aware():
    # JSON admin-config exposure (the endpoint the old heuristic missed)
    hit, _, ev = hunt._is_finding(
        Lead("http://h/rest/admin/application-configuration", "exposure", "fetch_url", "", "high"),
        'HTTP 200\n\n{"config":{"application":{"name":"x"}}}')
    assert hit and "JSON" in ev and "application-configuration" in ev
    # directory listing + metrics get descriptive labels
    _, _, ev2 = hunt._is_finding(Lead("http://h/ftp", "exposure", "fetch_url", "", "high"),
                                 "HTTP 200\n\n<title>listing directory /ftp</title>")
    assert "directory listing" in ev2
    _, _, ev3 = hunt._is_finding(Lead("http://h/metrics", "exposure", "fetch_url", "", "high"),
                                 "HTTP 200\n\n# HELP x\n# TYPE y")
    assert "Prometheus" in ev3


def test_seed_leads_cors_baseline_and_auth():
    leads = hunt.seed_leads("http://localhost:3001", DIRB + "\nrest/user/login (Status: 200)")
    cors = [l for l in leads if l.tool == "cors_check"]
    # a baseline CORS check on the base, plus one on the discovered auth endpoint
    assert any(l.url == "http://localhost:3001" for l in cors)
    assert any("login" in l.url and l.severity == "high" for l in cors)


def test_seed_leads_idor_from_crawled_ids():
    crawl = "\n".join([
        "http://localhost:3001/api/Users/1",     # path id -> idor
        "http://localhost:3001/api/Users/2",     # same template -> deduped
        "http://localhost:3001/rest/basket?id=3",  # query id -> idor
        "http://localhost:3001/about",           # no id -> ignored
    ])
    leads = hunt.seed_leads("http://localhost:3001", "", crawl)
    idor = [l for l in leads if l.tool == "idor_probe"]
    # one per template: /api/Users/{id} and /rest/basket?id=
    assert len(idor) == 2
    assert any("/api/Users/" in l.url for l in idor)
    assert any("basket" in l.url for l in idor)


def test_is_finding_idor_probe():
    hit, sev, ev = hunt._is_finding(
        Lead("http://h/api/Users/1", "idor", "idor_probe", ""),
        "HIGH: object refs enumerable by id (possible IDOR/BOLA) — ids 1, 2 ...")
    assert hit and sev == "high" and "IDOR" in ev
    assert not hunt._is_finding(Lead("http://h/x/1", "idor", "idor_probe", ""),
                                "no IDOR indicator (ids did not enumerate distinct objects)")[0]


def test_seed_leads_graphql_baseline():
    leads = hunt.seed_leads("http://localhost:3001", DIRB)
    assert any(l.tool == "graphql_scan" and l.vuln_class == "graphql" for l in leads)


def test_is_finding_graphql_scan():
    hit, sev, _ = hunt._is_finding(
        Lead("http://h/graphql", "graphql", "graphql_scan", ""),
        "MEDIUM: GraphQL introspection enabled at http://h/graphql — schema disclosed (40 types).")
    assert hit and sev == "medium"
    assert not hunt._is_finding(Lead("http://h/", "graphql", "graphql_scan", ""),
                                "no GraphQL endpoint found")[0]


def test_seed_leads_security_headers_baseline():
    leads = hunt.seed_leads("http://localhost:3001", DIRB)
    assert any(l.tool == "security_headers" and l.url == "http://localhost:3001"
               for l in leads)


def test_is_finding_security_headers():
    hit, sev, ev = hunt._is_finding(
        Lead("http://h/", "headers", "security_headers", ""),
        "MEDIUM: missing security headers: CSP, HSTS")
    assert hit and sev == "medium" and "headers" in ev
    assert not hunt._is_finding(Lead("http://h/", "headers", "security_headers", ""),
                                "security headers OK (no notable gaps)")[0]


def test_is_finding_cors_check():
    hit, sev, ev = hunt._is_finding(
        Lead("http://h/", "cors", "cors_check", ""),
        "CRITICAL: reflects arbitrary Origin (https://evil.example) with credentials")
    assert hit and sev == "critical" and "CORS" in ev
    assert not hunt._is_finding(Lead("http://h/", "cors", "cors_check", ""),
                                "no CORS misconfig (ACAO for https://evil.example: not returned)")[0]


def test_is_finding_secret_scan():
    hit, sev, ev = hunt._is_finding(
        Lead("http://h/.env", "secret", "secret_scan", ""),
        "CRITICAL: private key (----…EY)")
    assert hit and sev == "critical" and "leaked secret" in ev
    # a clean scan is not a finding
    assert not hunt._is_finding(Lead("http://h/x", "secret", "secret_scan", ""),
                                "no secrets found")[0]


def test_chain_exposure_to_secret_scan():
    # a readable exposed file -> secret_scan lead on the same url
    lead = Lead("http://h/ftp/package.json.bak", "exposure", "fetch_url", "", "high")
    fu = hunt.derive_followups(lead, Finding("exposure", lead.url, "high", "x"),
                               "http://h", "HTTP 200\n\n{...}")
    assert len(fu) == 1 and fu[0].tool == "secret_scan" and fu[0].url == lead.url
    # a directory listing is NOT secret-scanned (it fetches files instead)
    import redagent.hunt as _h
    orig = _h._list_links
    _h._list_links = lambda u: []
    try:
        fu2 = hunt.derive_followups(
            Lead("http://h/ftp", "exposure", "fetch_url", "", "high"),
            Finding("exposure", "http://h/ftp", "high", "l"),
            "http://h", "listing directory /ftp")
    finally:
        _h._list_links = orig
    assert not any(l.tool == "secret_scan" for l in fu2)


def test_chain_sqli_to_enumerate():
    lead = Lead("http://h/rest/products/search?q=apple", "sqli", "sql_test", "", "high")
    fu = hunt.derive_followups(lead, Finding("sqli", lead.url, "critical", "x"),
                               "http://h", "q is vulnerable")
    assert len(fu) == 1 and fu[0].tool == "sql_enumerate"


def test_chain_ftp_listing_resolves_and_filters(monkeypatch):
    monkeypatch.setattr(hunt, "_list_links", lambda url: [
        "ftp/coupons_2013.md.bak", "ftp/legal.md", "ftp/index.html", "ftp/"])
    lead = Lead("http://localhost:3001/ftp", "exposure", "fetch_url", "", "high")
    fu = hunt.derive_followups(lead, Finding("exposure", lead.url, "high", "l"),
                               "http://localhost:3001", "listing directory /ftp")
    urls = {l.url for l in fu}
    # sensitive-ext files resolved against BASE (no double /ftp/), non-sensitive dropped
    assert "http://localhost:3001/ftp/coupons_2013.md.bak" in urls
    assert "http://localhost:3001/ftp/legal.md" in urls
    assert not any("index.html" in u or u.endswith("/ftp/") for u in urls)
    assert not any("/ftp/ftp/" in u for u in urls)


def test_seed_https_adds_tls_lead():
    leads = hunt.seed_leads("https://shop.example:443", "")
    assert any(l.tool == "testssl_scan" for l in leads)


def test_seed_http_no_tls_lead():
    leads = hunt.seed_leads("http://localhost:3001", DIRB)
    assert not any(l.tool == "testssl_scan" for l in leads)


def test_seed_wordpress_detected():
    dirb = "wp-login.php (Status: 200)\nwp-content (Status: 301)"
    leads = hunt.seed_leads("http://localhost", dirb)
    assert any(l.tool == "wpscan_scan" and l.vuln_class == "wordpress" for l in leads)


def test_is_finding_jwt_and_testssl_and_wpscan():
    assert hunt._is_finding(Lead("tok", "auth", "jwt_test", ""),
                            "CRITICAL: alg:none — forgeable")[0]
    assert hunt._is_finding(Lead("h:443", "tls", "testssl_scan", ""),
                            " SSLv3 offered (NOT ok)")[0]
    assert hunt._is_finding(Lead("u", "wordpress", "wpscan_scan", ""),
                            "[!] Title: WP Core < 5.0 vuln")[0]
    # a clean JWT result is not a finding
    assert not hunt._is_finding(Lead("tok", "auth", "jwt_test", ""),
                                "header: {} payload: {} no alg:none / weak-secret issue found")[0]


def test_report_severity_ordered():
    findings = [Finding("misconfig", "u", "medium", "m"),
                Finding("sqli", "u", "critical", "c")]
    rep = hunt._report("http://h", findings)
    assert rep.index("Critical") < rep.index("Medium")
    assert "worst severity: critical" in rep


def test_report_includes_stack_when_given():
    rep = hunt._report("http://h", [], "HTTP 200 | title: Shop | tech: nginx, PHP")
    assert "**Stack:** HTTP 200 | title: Shop | tech: nginx, PHP" in rep
    # omitted when empty (unchanged report shape)
    assert "**Stack:**" not in hunt._report("http://h", [])
