"""Tool set. build_tools(cfg) returns plain functions bound to the config, so
each one enforces the engagement scope and writes inside the workspace. Every
tool that takes a URL/host calls cfg.scope.check() first and refuses otherwise.
"""

import re
import json
import shutil
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from ddgs import DDGS

from .scope import ScopeError


def _clean_params(url: str) -> str:
    """Strip manual SQL-injection syntax a model may have typed into a parameter
    value (e.g. q=apple' AND '1'='1 -> q=apple). sqlmap injects its OWN payloads,
    so each parameter just needs a clean, valid baseline value."""
    parts = urlparse(url)
    if not parts.query:
        return url
    cleaned = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        m = re.match(r"[A-Za-z0-9_.\-@ ]*", v)
        safe = (m.group(0) if m else "").strip()
        cleaned.append((k, safe or "1"))
    return urlunparse(parts._replace(query=urlencode(cleaned)))


def _nmap_trim(out: str) -> str:
    """nmap -sV dumps a huge service-fingerprint block for services it can't
    identify (the per-port `fingerprint-strings:` sub-blocks and the trailing
    SF-Port... submission block). That noise floods a small model and derails
    it mid-engagement; keep the port table and real script output, drop the
    fingerprint dump. Ports come from the table; headers come from fetch_url."""
    kept, skipping_fp = [], False
    for ln in out.splitlines():
        s = ln.strip()
        if ("unrecognized despite returning data" in s
                or s.startswith("==============NEXT SERVICE FINGERPRINT")
                or s.startswith("SF:") or s.startswith("SF-Port")):
            break
        if s.startswith("| fingerprint-strings:"):
            skipping_fp = True
            continue
        if skipping_fp:
            if s.startswith("|_"):      # script terminator: block done
                skipping_fp = False
            elif s.startswith("|"):     # still inside the fingerprint block
                continue
            else:                       # non-pipe line ends the block; keep it
                skipping_fp = False
                kept.append(ln)
            continue
        kept.append(ln)
    return "\n".join(kept).rstrip()


def build_tools(cfg):
    WS: Path = cfg.workspace
    WORDLIST = Path(__file__).resolve().parent / "wordlists" / "common_paths.txt"

    def _safe_path(path: str) -> Path:
        p = (WS / path).resolve()
        if not str(p).startswith(str(WS.resolve())):
            raise ValueError("path escapes workspace")
        return p

    def _have(binary: str) -> bool:
        return shutil.which(binary) is not None

    def _run(cmd: list[str], timeout: int | None = None) -> str:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout or cfg.tool_timeout, cwd=WS)
        except subprocess.TimeoutExpired:
            return "error: command timed out"
        return ((p.stdout or "") + (p.stderr or ""))[:4000] or f"(exit {p.returncode})"

    def web_search(query: str) -> str:
        """Look up CURRENT or EXTERNAL information you do not already know (latest
        versions, CVEs, docs, news). Not for this computer. Input: a search query."""
        try:
            results = DDGS().text(query, max_results=5)
        except Exception as e:
            return f"search error: {e}"
        return "\n".join(f"- {r.get('title')}: {r.get('body')}" for r in results) or "no results"

    def fetch_url(url: str) -> str:
        """Fetch a web page (GET) and return status, headers, and body start.
        Use to inspect a site/endpoint. Input: a full in-scope URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not url.startswith(("http://", "https://")):
            return "error: url must start with http:// or https://"
        req = urllib.request.Request(url, headers={"User-Agent": "redagent"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                return f"HTTP {r.status}\n{h}\n\n{r.read(8000).decode('utf-8','replace')[:4000]}"
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}\n{e.headers}\n\n{e.read(800).decode('utf-8','replace')}"
        except Exception as e:
            return f"fetch error: {e}"

    def http_request(method: str, url: str, headers: str = "", body: str = "") -> str:
        """Send a custom HTTP request (any method/headers/body) to an in-scope URL.
        Use for logins, APIs, and injection tests. headers = JSON object string."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        hdrs = {"User-Agent": "redagent"}
        if headers.strip():
            try:
                hdrs.update(json.loads(headers))
            except json.JSONDecodeError:
                return "error: headers must be a JSON object string"
        req = urllib.request.Request(url, data=body.encode() if body else None,
                                     headers=hdrs, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                h = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                return f"HTTP {r.status}\n{h}\n\n{r.read(2500).decode('utf-8','replace')}"
        except urllib.error.HTTPError as e:
            return f"HTTP {e.code}\n{e.headers}\n\n{e.read(1500).decode('utf-8','replace')}"
        except Exception as e:
            return f"request error: {e}"

    def nmap_web_scan(target: str) -> str:
        """Scan an in-scope host for common web ports + service versions (safe
        fixed scripts). Input: a hostname or IP."""
        try:
            host = cfg.scope.check(target)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        return _nmap_trim(_run(
            ["nmap", "-sV", "-Pn", "-p", "80,443,3000,3001,8080,8443",
             "--script", "http-title,http-headers,http-methods", "--", host]))

    def dir_bruteforce(url: str) -> str:
        """Discover hidden directories/endpoints on an in-scope web server
        (gobuster + bundled wordlist, with SPA wildcard handling). Input: base URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        cmd = ["gobuster", "dir", "-u", url, "-w", str(WORDLIST), "-q", "-t", "20",
               "--no-error", "-k"]
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                cmd += ["--exclude-length", str(len(r.read()))]
        except Exception:
            pass
        return _run(cmd)

    def sql_test(url: str, data: str = "") -> str:
        """Test an in-scope URL for SQL injection with sqlmap (non-interactive).
        Input: a full URL whose query holds the parameter to test
        (http://host/rest/products/search?q=apple). Pass `data` ONLY for a real
        POST body with DIFFERENT fields — never repeat a query param in `data`."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)  # strip any manual SQL the model typed into params
        # The 7B often echoes a URL query param into `data` too (data="q=apple"
        # for ?q=apple). sqlmap then treats it as a POST body, tests the wrong
        # channel ("POST parameter 'q' does not appear to be dynamic") and misses
        # the GET injection. Drop data keys already in the query; keep genuine
        # POST-only keys so real POST bodies still work.
        if data:
            query_keys = {k for k, _ in parse_qsl(urlparse(url).query,
                                                   keep_blank_values=True)}
            data = "&".join(kv for kv in data.split("&")
                            if kv.split("=", 1)[0] not in query_keys)
        # --technique=BEU drops the slow time-based (T) and stacked (S) tests,
        # which otherwise take minutes per URL and blow the engagement budget.
        # Boolean + Error + Union is enough to confirm most injections.
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--technique=BEU", "--flush-session", "--disable-coloring"]
        if data:
            cmd += ["--data", data]
        out = _run(cmd)
        keep = [ln for ln in out.splitlines() if any(k in ln.lower() for k in
                ("injectable", "parameter", "payload", "back-end dbms",
                 "vulnerable", "does not seem", "type:", "title:"))]
        return "\n".join(keep)[:3000] or out[-1500:]

    def sql_enumerate(url: str) -> str:
        """Post-exploitation of a CONFIRMED SQL injection: enumerate the database
        tables via sqlmap on an in-scope URL. Run only after sql_test confirmed
        'q is vulnerable'. Input: the same URL+param (q=apple) that was injectable."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--technique=BEU", "--tables", "--disable-coloring"]
        out = _run(cmd, timeout=240)
        # Keep real table rows (| Name |) + the Database/count lines; drop sqlmap's
        # ASCII-art banner, which also starts with '|' and would pollute evidence.
        row = re.compile(r"^\|\s*[A-Za-z_][\w$]*\s*\|$")
        keep = [ln for ln in out.splitlines()
                if row.match(ln.strip()) or "Database:" in ln
                or re.search(r"\[\d+ tables?\]", ln)]
        return "\n".join(keep)[:3000] or "(no tables enumerated)"

    def vuln_scan(url: str) -> str:
        """Scan an in-scope web app for known vulns/misconfig with nuclei.
        Input: a base URL."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        # Tag-filter keeps nuclei fast (exposures/misconfig/default-logins) instead
        # of running the full template set, which blows the engagement time budget.
        # Broad coverage: run the full template set (no tag restriction) filtered to
        # medium+ severity so CVEs, misconfig, exposures, takeovers, injection, etc.
        # are all checked. Severity filter keeps it from running forever on info noise.
        out = _run(["nuclei", "-u", url, "-silent", "-nc",
                    "-severity", "medium,high,critical"], timeout=300)
        # Drop nuclei/Go runtime noise (e.g. the harmless sonic/ast CPU warning)
        # so the model never mistakes a warning for a finding. Real findings look
        # like "[template-id] [proto] [severity] url".
        findings = [ln for ln in out.splitlines()
                    if ln.strip() and "sonic/ast" not in ln
                    and not ln.lower().startswith("warning")]
        return "\n".join(findings) or "(no findings)"

    def xss_test(url: str) -> str:
        """Test an in-scope URL with parameters for cross-site scripting (XSS)
        using dalfox. Input: a URL with a query parameter, e.g.
        http://localhost:3001/rest/products/search?q=apple ."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        url = _clean_params(url)  # dalfox injects its own payloads; strip any the
                                  # model hand-typed (q=<script>...> -> q=1)
        out = _run(["dalfox", "url", url, "--no-color", "--no-spinner",
                    "--silence", "--skip-bav"], timeout=240)
        lines = [ln for ln in out.splitlines()
                 if any(k in ln for k in ("[POC]", "[VULN]", "[G]", "[R]", "triggered", "reflected"))]
        return "\n".join(lines)[:3000] or "(no XSS reported)"

    def read_file(path: str) -> str:
        """Read a text file from the workspace. Input: a relative filename."""
        try:
            return _safe_path(path).read_text(encoding="utf-8")[:8000]
        except Exception as e:
            return f"read error: {e}"

    def write_file(path: str, content: str) -> str:
        """Save text to a file in the workspace. Inputs: relative filename + content."""
        try:
            fp = _safe_path(path)
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content, encoding="utf-8")
            return f"wrote {len(content)} chars to {fp.relative_to(WS)}"
        except Exception as e:
            return f"write error: {e}"

    def nikto_scan(url: str) -> str:
        """Scan an in-scope web server for misconfig/outdated software/dangerous
        files with nikto. Input: a base URL. Broad but noisy; use once per host."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("nikto"):
            return "error: nikto not installed (sudo pacman -S nikto)"
        out = _run(["nikto", "-h", url, "-ask", "no", "-nointeractive",
                    "-maxtime", "120s"], timeout=150)
        keep = [ln for ln in out.splitlines()
                if ln.startswith("+ ") and "0 host(s) tested" not in ln]
        return "\n".join(keep)[:3000] or "(no notable nikto findings)"

    def wpscan_scan(url: str) -> str:
        """Scan an in-scope WordPress site for vulnerable core/plugins/themes and
        exposed users with wpscan. Input: a base URL. WordPress targets only."""
        try:
            cfg.scope.check(url)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        if not _have("wpscan"):
            return "error: wpscan not installed (sudo pacman -S wpscan)"
        out = _run(["wpscan", "--url", url, "--no-banner", "--random-user-agent",
                    "--format", "cli-no-color"], timeout=240)
        keep = [ln for ln in out.splitlines() if ln.strip().startswith(("[+]", "[!]", "[i]"))]
        return "\n".join(keep)[:3000] or out[-1500:]

    def testssl_scan(target: str) -> str:
        """Check an in-scope HTTPS endpoint's TLS config for weak protocols,
        ciphers, and cert issues with testssl.sh. Input: host:port (e.g.
        example.com:443). Only meaningful for TLS/HTTPS services."""
        try:
            cfg.scope.check(target)
        except ScopeError as e:
            return f"refused (out of scope): {e}"
        binary = "testssl" if _have("testssl") else "testssl.sh"
        if not _have(binary):
            return "error: testssl not installed (sudo pacman -S testssl.sh)"
        out = _run([binary, "--quiet", "--color", "0", "--warnings", "off",
                    target], timeout=300)
        keep = [ln for ln in out.splitlines()
                if any(k in ln for k in ("VULNERABLE", "NOT ok", "offered", "WEAK",
                                         "insecure", "expired", "self signed"))]
        return "\n".join(keep)[:3000] or "(no TLS issues surfaced; or not an HTTPS port)"

    def jwt_test(token: str) -> str:
        """Decode a JSON Web Token and flag weaknesses: 'alg:none' acceptance and
        a weak HMAC signing secret (dictionary check). Input: the raw JWT string.
        No network/scope — operates on a token you already captured."""
        import base64, hashlib, hmac, json as _json
        def _b64(seg: str) -> bytes:
            return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        parts = token.strip().split(".")
        if len(parts) < 2:
            return "error: not a JWT (expected header.payload.signature)"
        try:
            header = _json.loads(_b64(parts[0]))
            payload = _json.loads(_b64(parts[1]))
        except Exception as e:
            return f"error: cannot decode JWT ({e})"
        findings = []
        alg = str(header.get("alg", "")).lower()
        if alg in ("none", ""):
            findings.append("CRITICAL: alg:none — signature not verified, token is forgeable.")
        if alg.startswith("hs") and len(parts) == 3:
            signing = f"{parts[0]}.{parts[1]}".encode()
            sig = _b64(parts[2])
            digest = {"hs256": hashlib.sha256, "hs384": hashlib.sha384,
                      "hs512": hashlib.sha512}.get(alg)
            weak = ["secret", "password", "changeme", "jwt", "key", "admin", "test",
                    "1234", "123456", "qwerty", "secretkey", "supersecret", "token"]
            for cand in weak:
                if digest and hmac.compare_digest(
                        hmac.new(cand.encode(), signing, digest).digest(), sig):
                    findings.append(f"HIGH: weak HMAC secret cracked = '{cand}' — "
                                    "tokens can be forged.")
                    break
        head = _json.dumps(header)
        body = _json.dumps(payload)[:800]
        return (f"header: {head}\npayload: {body}\n"
                + ("\n".join(findings) if findings else "no alg:none / weak-secret issue found"))

    return {
        "web_search": web_search, "fetch_url": fetch_url, "http_request": http_request,
        "nmap_web_scan": nmap_web_scan, "dir_bruteforce": dir_bruteforce,
        "sql_test": sql_test, "sql_enumerate": sql_enumerate,
        "vuln_scan": vuln_scan, "xss_test": xss_test,
        "nikto_scan": nikto_scan, "wpscan_scan": wpscan_scan,
        "testssl_scan": testssl_scan, "jwt_test": jwt_test,
        "read_file": read_file, "write_file": write_file,
    }
