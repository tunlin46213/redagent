"""Scope guard (RoE) — the authorization gate. Locks in the placeholder fix."""

import pytest

from redagent.scope import Scope, ScopeError


def s():
    return Scope(["localhost", "127.0.0.1", "10.0.0.0/8"])


def test_literal_host_in_scope():
    assert s().check("http://localhost:3001/x") == "localhost"


def test_ip_in_allowed_net():
    assert s().check("http://10.1.2.3/") == "10.1.2.3"


def test_out_of_scope_raises():
    with pytest.raises(ScopeError, match="not in the authorized scope"):
        s().check("http://scanme.nmap.org/")


@pytest.mark.parametrize("ph", ["host", "example.com", "target", "yourhost", "foo.test"])
def test_placeholder_hosts_get_placeholder_message(ph):
    with pytest.raises(ScopeError, match="placeholder"):
        s().check(f"http://{ph}/path")


def test_catch_all_scope_rejected():
    with pytest.raises(ScopeError, match="catch-all"):
        Scope(["0.0.0.0/0"])


def test_expired_window_refused():
    sc = Scope(["localhost"], authorized_until="2000-01-01")
    with pytest.raises(ScopeError, match="window ended"):
        sc.check("http://localhost/")


def test_host_parsed_from_url_and_bare():
    assert s()._host_of("http://localhost:3001/a") == "localhost"
    assert s()._host_of("localhost:3001") == "localhost"
