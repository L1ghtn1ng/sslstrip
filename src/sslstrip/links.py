"""TTL-bounded LRU store of URLs that must be fetched over HTTPS."""

from collections import OrderedDict
from dataclasses import dataclass
from time import monotonic
from urllib.parse import urldefrag


@dataclass(frozen=True, slots=True)
class SecureTarget:
    """HTTPS origin details for a stripped HTTP URL."""

    port: int


class SecureLinkStore:
    """Map ``(client, http_url)`` to the original HTTPS port.

    Entries expire after ``ttl_seconds`` of inactivity and the store evicts the
    least-recently-used item when ``limit`` is exceeded.
    """

    def __init__(self, ttl_seconds: float, limit: int) -> None:
        self._ttl = ttl_seconds
        self._limit = limit
        self._entries: OrderedDict[tuple[str, str], tuple[int, float]] = OrderedDict()

    def add(self, client: str, http_url: str, https_port: int) -> None:
        """Record that ``http_url`` for ``client`` should be fetched via HTTPS."""
        self._purge_expired()
        key = _link_key(client, http_url)
        self._entries[key] = (https_port, monotonic())
        self._entries.move_to_end(key)
        while len(self._entries) > self._limit:
            self._entries.popitem(last=False)

    def get(self, client: str, http_url: str) -> int | None:
        """Return the HTTPS port if the link is still cached, else None."""
        key = _link_key(client, http_url)
        item = self._entries.get(key)
        if item is None:
            return None
        port, seen = item
        now = monotonic()
        if now - seen > self._ttl:
            del self._entries[key]
            return None
        self._entries[key] = (port, now)
        self._entries.move_to_end(key)
        return port

    def __len__(self) -> int:
        self._purge_expired()
        return len(self._entries)

    def _purge_expired(self) -> None:
        now = monotonic()
        expired = [key for key, (_, seen) in self._entries.items() if now - seen > self._ttl]
        for key in expired:
            del self._entries[key]


def _link_key(client: str, http_url: str) -> tuple[str, str]:
    return client, urldefrag(http_url).url
