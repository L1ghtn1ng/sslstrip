"""TTL/LRU secure-link store tests."""

import pytest

from sslstrip.links import SecureLinkStore


def test_round_trip_port() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    store.add('1.2.3.4', 'http://example.com:8443/app', 8443)
    assert store.get('1.2.3.4', 'http://example.com:8443/app') == 8443


def test_missing_is_none() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    assert store.get('1.2.3.4', 'http://example.com/') is None


def test_ttl_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    times = iter([100.0, 100.0, 200.0])

    def _monotonic() -> float:
        return next(times)

    monkeypatch.setattr('sslstrip.links.monotonic', _monotonic)
    store = SecureLinkStore(ttl_seconds=10, limit=10)
    store.add('c', 'http://example.com/', 443)
    assert store.get('c', 'http://example.com/') is None


def test_lru_eviction() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=2)
    store.add('c', 'http://a.example/', 443)
    store.add('c', 'http://b.example/', 443)
    store.add('c', 'http://c.example/', 443)
    assert store.get('c', 'http://a.example/') is None
    assert store.get('c', 'http://b.example/') == 443
    assert store.get('c', 'http://c.example/') == 443


def test_lru_refresh_on_get() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=2)
    store.add('c', 'http://a.example/', 443)
    store.add('c', 'http://b.example/', 443)
    assert store.get('c', 'http://a.example/') == 443
    store.add('c', 'http://c.example/', 443)
    assert store.get('c', 'http://b.example/') is None
    assert store.get('c', 'http://a.example/') == 443
    assert len(store) == 2


def test_len_purges_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    times = iter([100.0, 100.0, 200.0])

    def _monotonic() -> float:
        return next(times)

    monkeypatch.setattr('sslstrip.links.monotonic', _monotonic)
    store = SecureLinkStore(ttl_seconds=10, limit=10)
    store.add('c', 'http://example.com/', 443)
    assert len(store) == 0


def test_fragment_variants_share_one_routing_key() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    store.add('client', 'http://example.test/page#one', 443)
    store.add('client', 'http://example.test/page#two', 8443)
    assert len(store) == 1
    assert store.get('client', 'http://example.test/page') == 8443
