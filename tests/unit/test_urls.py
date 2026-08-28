"""URL normalization tests, including explicit HTTPS ports."""

import pytest

from sslstrip.urls import (
    InvalidAuthorityError,
    canonical_http_url,
    decode_request_uri,
    https_url_to_http,
    origin_form_path,
    request_http_url,
    split_host_header,
    upstream_url,
)


def test_decode_request_uri_accepts_bytes() -> None:
    assert decode_request_uri(b'http://example.com/path') == 'http://example.com/path'


def test_origin_form_from_absolute_http_uri() -> None:
    assert origin_form_path('http://example.com/login?x=1') == '/login?x=1'


def test_https_explicit_port_is_retained() -> None:
    http_url, port = https_url_to_http('https://bank.example:8443/app')
    assert port == 8443
    assert http_url == 'http://bank.example:8443/app'


def test_https_default_port_is_omitted() -> None:
    http_url, port = https_url_to_http('https://bank.example:443/app')
    assert port == 443
    assert http_url == 'http://bank.example/app'


def test_https_fragment_is_preserved_in_visible_url() -> None:
    http_url, port = https_url_to_http('https://bank.example/app?q=1#section')
    assert port == 443
    assert http_url == 'http://bank.example/app?q=1#section'
    assert https_url_to_http('https://bank.example/app#') == ('http://bank.example/app#', 443)


def test_split_host_header_with_port() -> None:
    host, port = split_host_header('example.com:8080')
    assert host == 'example.com'
    assert port == 8080


def test_invalid_host_is_rejected() -> None:
    with pytest.raises(InvalidAuthorityError):
        split_host_header('')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('example.com:99999')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('exa mple.com')


def test_request_http_url_from_origin_form() -> None:
    url, host, port, path = request_http_url('example.com', b'/foo?bar=1')
    assert host == 'example.com'
    assert port is None
    assert path == '/foo?bar=1'
    assert url == 'http://example.com/foo?bar=1'


def test_request_http_url_from_absolute_form_bytes() -> None:
    url, host, port, path = request_http_url('example.com', b'http://example.com/abs')
    assert path == '/abs'
    assert url == 'http://example.com/abs'
    del host, port


def test_canonical_ipv6() -> None:
    assert canonical_http_url('::1', 8080, '/') == 'http://[::1]:8080/'


def test_upstream_https_url() -> None:
    assert upstream_url(secure=True, hostname='example.com', port=8443, path='/x') == 'https://example.com:8443/x'
    assert upstream_url(secure=True, hostname='example.com', port=443, path='/x') == 'https://example.com/x'
    assert upstream_url(secure=False, hostname='example.com', port=80, path='x?q=1') == 'http://example.com/x?q=1'


def test_origin_form_without_slash() -> None:
    assert origin_form_path('login') == '/login'
    assert origin_form_path('https://example.com') == '/'


def test_ipv6_host_header() -> None:
    host, port = split_host_header('[::1]:8080')
    assert host == '::1'
    assert port == 8080
    host, port = split_host_header('[::1]')
    assert host == '::1'
    assert port is None
    with pytest.raises(InvalidAuthorityError):
        split_host_header('[::1')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('[::1]oops')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('[]')


def test_https_url_errors() -> None:
    with pytest.raises(InvalidAuthorityError, match='not an https'):
        https_url_to_http('http://example.com/')
    with pytest.raises(InvalidAuthorityError, match='missing host'):
        https_url_to_http('https:///path')


def test_https_url_malformed_port_and_ipv6() -> None:
    with pytest.raises(InvalidAuthorityError, match='port'):
        https_url_to_http('https://example.com:abc/x')
    with pytest.raises(InvalidAuthorityError, match='port'):
        https_url_to_http('https://example.com:99999/x')
    with pytest.raises(InvalidAuthorityError):
        https_url_to_http('https://[::1/x')


def test_invalid_hostname_labels() -> None:
    with pytest.raises(InvalidAuthorityError):
        split_host_header('example..com')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('-example.com')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('example.com-')
    with pytest.raises(InvalidAuthorityError):
        split_host_header(':80')
    with pytest.raises(InvalidAuthorityError):
        split_host_header('example.com:')
    assert split_host_header('localhost') == ('localhost', None)
