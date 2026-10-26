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
