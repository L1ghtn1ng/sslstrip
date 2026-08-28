"""HTML/CSS/Location rewriting and charset handling."""

from sslstrip.links import SecureLinkStore
from sslstrip.rewrite import (
    decode_text,
    discover_relative_links,
    encode_text,
    is_rewritable,
    rewrite_https_references,
    rewrite_location,
)


def test_is_rewritable() -> None:
    assert is_rewritable('text/html; charset=utf-8')
    assert is_rewritable('text/css')
    assert not is_rewritable('image/png')
    assert not is_rewritable(None)


def test_rewrite_https_and_record_port() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    html = '<a href="https://secure.example:8443/login">x</a>'
    rewritten = rewrite_https_references(html, '1.2.3.4', store)
    assert 'https://' not in rewritten
    assert 'http://secure.example:8443/login' in rewritten
    assert store.get('1.2.3.4', 'http://secure.example:8443/login') == 8443


def test_rewrite_records_browser_decoded_entity_url() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    html = '<a href="https://secure.example/path?a=1&amp;b=2">x</a>'
    rewritten = rewrite_https_references(html, '1.2.3.4', store)
    assert rewritten == '<a href="http://secure.example/path?a=1&amp;b=2">x</a>'
    assert store.get('1.2.3.4', 'http://secure.example/path?a=1&b=2') == 443


def test_location_header() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    assert rewrite_location('https://example.com/next', 'c', store) == 'http://example.com/next'
    assert store.get('c', 'http://example.com/next') == 443


def test_fragments_are_visible_but_not_part_of_routing_keys() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    rewritten = rewrite_https_references('https://example.com/page?q=1#section', 'c', store)
    assert rewritten == 'http://example.com/page?q=1#section'
    assert store.get('c', 'http://example.com/page?q=1') == 443
    assert len(store) == 1

    location = rewrite_location('https://example.com/next#details', 'c', store)
    assert location == 'http://example.com/next#details'
    assert store.get('c', 'http://example.com/next') == 443

    assert rewrite_https_references('https://example.com/empty#)', 'c', store) == 'http://example.com/empty#)'
    assert rewrite_location('https://example.com/redirect#', 'c', store) == 'http://example.com/redirect#'


def test_relative_html_links_from_secure_page() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    html = '<html><a href="login">L</a><img src="/logo.png"></html>'
    discover_relative_links(
        html,
        content_type='text/html',
        https_base='https://secure.example/app/page',
        client='c',
        store=store,
    )
    assert store.get('c', 'http://secure.example/app/login') == 443
    assert store.get('c', 'http://secure.example/logo.png') == 443


def test_relative_fragment_link_uses_fragmentless_key() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    discover_relative_links(
        '<a href="next#section">next</a>',
        content_type='text/html',
        https_base='https://secure.example/app/page',
        client='c',
        store=store,
    )
    assert store.get('c', 'http://secure.example/app/next') == 443


def test_relative_css_links() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    css = 'body { background: url(images/bg.png); }'
    discover_relative_links(
        css,
        content_type='text/css',
        https_base='https://secure.example/style.css',
        client='c',
        store=store,
    )
    assert store.get('c', 'http://secure.example/images/bg.png') == 443


def test_html_base_and_css_import_are_resolved_securely() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    discover_relative_links(
        '<base href="/other/"><a href="next#section">next</a>',
        content_type='text/html',
        https_base='https://secure.example/app/page',
        client='c',
        store=store,
    )
    discover_relative_links(
        '@import "theme/base.css";',
        content_type='text/css',
        https_base='https://secure.example/styles/main.css',
        client='c',
        store=store,
    )
    assert store.get('c', 'http://secure.example/other/next') == 443
    assert store.get('c', 'http://secure.example/styles/theme/base.css') == 443


def test_relative_location_from_secure_page_is_recorded() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    location = rewrite_location('/login#section', 'c', store, https_base='https://secure.example/app/page')
    assert location == '/login#section'
    assert store.get('c', 'http://secure.example/login') == 443


def test_charset_round_trip() -> None:
    text, charset = decode_text('café'.encode('latin-1'), 'text/html; charset=iso-8859-1')
    assert charset.lower() in {'iso-8859-1', 'latin-1'}
    assert 'caf' in text
    encoded = encode_text(text, charset)
    assert encoded == 'café'.encode('latin-1')


def test_unknown_charset_falls_back() -> None:
    text, charset = decode_text(b'hello', 'text/html; charset=not-a-codec')
    assert charset == 'utf-8'
    assert text == 'hello'
    assert encode_text('hello', 'not-a-codec') == b'hello'


def test_surrogateescape_on_decode_error() -> None:
    text, charset = decode_text(b'\xff', 'text/plain; charset=utf-8')
    assert charset == 'utf-8'
    assert encode_text(text, 'utf-8')


def test_skip_javascript_and_http_links() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    html = '<a href="javascript:void(0)">x</a><a href="data:text/plain,hi">y</a><a href="http://plain.example/">z</a><a href="#frag">f</a>'
    discover_relative_links(
        html,
        content_type='text/html',
        https_base='https://secure.example/app',
        client='c',
        store=store,
    )
    assert len(store) == 0


def test_absolute_https_in_html() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    html = '<a href="https://other.example/x">x</a>'
    discover_relative_links(
        html,
        content_type='text/html',
        https_base='https://secure.example/',
        client='c',
        store=store,
    )
    assert store.get('c', 'http://other.example/x') == 443


def test_location_non_https() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    assert rewrite_location('/relative', 'c', store) == '/relative'


def test_invalid_https_left_alone() -> None:
    store = SecureLinkStore(ttl_seconds=60, limit=10)
    rewritten = rewrite_https_references('see https:///', 'c', store)
    assert 'https:///' in rewritten


def test_parse_charset_defaults() -> None:
    from sslstrip.rewrite import parse_charset

    assert parse_charset(None) == 'utf-8'
    assert parse_charset('text/html') == 'utf-8'
    assert parse_charset('text/html; charset=""') == 'utf-8'
