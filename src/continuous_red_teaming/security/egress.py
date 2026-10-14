"""Egress control for target endpoints.

The platform calls URLs that operators register, which makes it a potential
server-side request forgery pivot. Every target and trace endpoint is
checked at registration and again before each run:

* scheme must be https (http only when explicitly enabled for development);
* no userinfo in the URL (credentials come from the credential provider);
* the host must match an operator-configured allow list (glob patterns);
* IP literals in link-local (cloud metadata), multicast, unspecified or
  reserved ranges are always refused.

DNS rebinding is out of scope for a URL check; the Helm NetworkPolicy limits
egress to the ports the platform needs as a second layer.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from collections.abc import Sequence
from urllib.parse import urlsplit

from continuous_red_teaming.domain.errors import TargetPolicyError


class EgressPolicy:
    def __init__(self, allowed_hosts: Sequence[str], *, allow_insecure: bool = False) -> None:
        self._allowed = tuple(h.casefold() for h in allowed_hosts)
        self._allow_insecure = allow_insecure

    def check(self, url: str) -> str:
        parts = urlsplit(url)
        schemes = {"https", "http"} if self._allow_insecure else {"https"}
        if parts.scheme not in schemes:
            raise TargetPolicyError(f"scheme {parts.scheme or '<none>'!r} is not permitted")
        if parts.username or parts.password:
            raise TargetPolicyError("credentials in target URLs are not permitted")
        host = (parts.hostname or "").casefold()
        if not host:
            raise TargetPolicyError("target URL has no host")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and (
            address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise TargetPolicyError(f"address {host} is in a refused range")
        if not any(fnmatch.fnmatchcase(host, pattern) for pattern in self._allowed):
            raise TargetPolicyError(f"host {host} is not in the target allow list")
        return url
