"""Engagement scope guard (RoE). Every tool that touches a target routes through
check_target() first. Only targets declared in config.scope.allowed_targets run;
anything else is refused — which protects against the agent hallucinating a target
as much as against hitting an out-of-scope host.
"""

import ipaddress
import socket
from datetime import date
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is outside the authorized engagement scope."""


class Scope:
    def __init__(self, allowed: list[str], authorized_until: str = ""):
        self.hosts: set[str] = set()
        self.nets: list[ipaddress._BaseNetwork] = []
        for entry in allowed:
            entry = str(entry).strip()
            if not entry:
                continue
            try:
                self.nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self.hosts.add(entry.lower())
        self.authorized_until = authorized_until.strip()
        # 0.0.0.0/0 or ::/0 would disable the guard — reject it outright.
        for net in self.nets:
            if net.prefixlen == 0:
                raise ScopeError(
                    "refusing a catch-all scope (0.0.0.0/0); list specific "
                    "authorized targets instead"
                )

    def _host_of(self, target: str) -> str:
        if "://" in target:
            return (urlparse(target).hostname or "").lower()
        return target.split("/")[0].split(":")[0].lower()

    def check(self, target: str) -> str:
        """Return the bare host if in scope, else raise ScopeError."""
        if self.authorized_until:
            try:
                if date.today() > date.fromisoformat(self.authorized_until):
                    raise ScopeError(f"engagement window ended {self.authorized_until}")
            except ValueError:
                pass
        host = self._host_of(target)
        if not host:
            raise ScopeError(f"could not parse a host from '{target}'")
        if host in self.hosts:
            return host
        # Catch an invented placeholder BEFORE DNS resolution — otherwise a name
        # like 'host' can resolve via a search domain into an allowed net and be
        # wrongly admitted. A placeholder is never a real engagement target.
        if host in _PLACEHOLDER_HOSTS or host.endswith((".example", ".invalid", ".test")):
            raise ScopeError(
                f"'{host}' is a placeholder, not a real target. Reuse the actual "
                f"host from the task (e.g. localhost:3001) in the URL and retry."
            )
        # Resolve to IP and test against allowed networks / IP literals.
        try:
            ip = ipaddress.ip_address(host)
            candidates = [ip]
        except ValueError:
            try:
                candidates = [ipaddress.ip_address(socket.gethostbyname(host))]
            except Exception:
                candidates = []
        for ip in candidates:
            if str(ip) in self.hosts:
                return host
            if any(ip in net for net in self.nets):
                return host
        raise ScopeError(
            f"'{host}' is not in the authorized scope. Add it to "
            f"config.yaml scope.allowed_targets if you are authorized to test it."
        )


_PLACEHOLDER_HOSTS = {
    "host", "hostname", "target", "yourhost", "your-host", "example.com",
    "www.example.com", "example.org", "example.net", "domain", "domain.com",
    "yourdomain.com", "site.com", "test.com", "localhost.localdomain", "server",
}
