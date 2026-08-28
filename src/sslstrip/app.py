"""Process-owned application state (no global singletons)."""

from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Protocol

from sslstrip.config import AppConfig
from sslstrip.cookies import SessionExpirer
from sslstrip.links import SecureLinkStore
from sslstrip.logs import TrafficLog
from sslstrip.upstream import UpstreamResponse


class Fetch(Protocol):
    """Upstream fetch used by the request handler."""

    def __call__(
        self,
        *,
        method: bytes,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        timeout: float,
        max_body_size: int,
    ) -> Awaitable[UpstreamResponse]: ...


@dataclass
class App:
    """Runtime objects shared by the proxy factory and request handler."""

    config: AppConfig
    links: SecureLinkStore
    sessions: SessionExpirer
    traffic: TrafficLog
    fetch: Fetch
