"""Hop-by-hop stripping and multi-value preservation."""

from sslstrip.headers import (
    drop_headers,
    filter_request_headers,
    filter_response_headers,
    first_header,
    header_values,
    replace_header,
)


def test_hop_by_hop_removed() -> None:
    headers = [
        ('Accept', 'text/html'),
        ('Connection', 'keep-alive, Upgrade'),
        ('Upgrade', 'websocket'),
        ('Keep-Alive', 'timeout=5'),
        ('Host', 'example.com'),
    ]
    filtered = filter_request_headers(headers)
    names = {name.lower() for name, _ in filtered}
    assert 'connection' not in names
    assert 'upgrade' not in names
    assert 'keep-alive' not in names
    assert 'host' not in names
    assert 'accept' in names


def test_set_cookie_multi_value_preserved() -> None:
    headers = [
        ('Set-Cookie', 'a=1'),
        ('Set-Cookie', 'b=2'),
        ('Content-Type', 'text/html'),
        ('ETag', '"abc"'),
    ]
    filtered = filter_response_headers(headers, body_changed=True)
    cookies = header_values(filtered, 'set-cookie')
    assert cookies == ['a=1', 'b=2']
    names = {name.lower() for name, _ in filtered}
    assert 'etag' not in names
    assert 'content-length' not in names


def test_drop_and_replace() -> None:
    headers = [('A', '1'), ('B', '2'), ('A', '3')]
    assert drop_headers(headers, ['a']) == [('B', '2')]
    replaced = replace_header(headers, 'A', '9')
    assert first_header(replaced, 'a') == '9'
    assert first_header(headers, 'missing') is None
