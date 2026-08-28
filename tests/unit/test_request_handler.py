"""Regression tests for request validation, rewriting, cookies, and errors."""

import asyncio
import gzip
from io import BytesIO
from pathlib import Path
from typing import override

from tests.fakes import FakeRequest, sample_config

from sslstrip.app import App
from sslstrip.cookies import SessionExpirer
from sslstrip.errors import ProxyTimeoutError
from sslstrip.links import SecureLinkStore
from sslstrip.logs import TrafficLog
from sslstrip.request_handler import UpstreamTarget, _outbound_headers, _ResponseBodyProducer, handle_request
from sslstrip.upstream import ResponseBody, UpstreamResponse


def _app(
    *,
    kill_sessions: bool = False,
    response: UpstreamResponse | None = None,
    error: BaseException | None = None,
    traffic: TrafficLog | None = None,
) -> App:
    async def fetch(
        *,
        method: bytes,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        timeout: float,
        max_body_size: int,
    ) -> UpstreamResponse:
        del method, url, headers, body, timeout, max_body_size
        if error is not None:
            raise error
        if response is None:
            raise RuntimeError('fetch not configured')
        return response

    return App(
        config=sample_config(kill_sessions=kill_sessions, max_body_size=1024 * 1024),
        links=SecureLinkStore(ttl_seconds=1800, limit=100),
        sessions=SessionExpirer(enabled=kill_sessions),
        traffic=traffic if traffic is not None else TrafficLog('off', None),
        fetch=fetch,
    )


def _run(request: FakeRequest, app: App) -> None:
    asyncio.run(handle_request(request, app))


def test_bytes_absolute_uri_does_not_crash() -> None:
    request = FakeRequest(uri=b'http://example.com/abs-path', host='example.com')
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], b'ok')))
    assert request.finished
    assert request.code == 200
    assert request.body == b'ok'


def test_missing_host_is_400() -> None:
    request = FakeRequest(host=None)
    _run(request, _app())
    assert request.code == 400


def test_connect_is_405() -> None:
    request = FakeRequest(method=b'CONNECT', uri=b'example.com:443')
    _run(request, _app())
    assert request.code == 405


def test_websocket_upgrade_is_426() -> None:
    request = FakeRequest(extra_headers=[(b'Connection', b'Upgrade'), (b'Upgrade', b'websocket')])
    _run(request, _app())
    assert request.code == 426


def test_kill_sessions_expires_then_passes() -> None:
    app = _app(kill_sessions=True, response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], b'ok'))
    first = FakeRequest(extra_headers=[(b'Cookie', b'sid=abc')])
    _run(first, app)
    assert first.code == 302
    cookies = [name for name, _values in first.responseHeaders.items if name.lower() == b'set-cookie']
    assert cookies
    second = FakeRequest(extra_headers=[(b'Cookie', b'sid=abc')])
    _run(second, app)
    assert second.code == 200
    assert second.body == b'ok'


def test_html_gzip_rewritten() -> None:
    html = b'<a href="https://secure.example:8443/login">x</a>'
    encoded = gzip.compress(html)
    app = _app(
        response=UpstreamResponse(
            200,
            b'OK',
            [('Content-Type', 'text/html'), ('Content-Encoding', 'gzip')],
            encoded,
        )
    )
    request = FakeRequest()
    _run(request, app)
    decoded = gzip.decompress(request.body)
    assert b'https://' not in decoded
    assert b'http://secure.example:8443/login' in decoded
    assert app.links.get('192.0.2.10', 'http://secure.example:8443/login') == 8443


def test_secure_upstream_multiple_set_cookie() -> None:
    app = _app(
        response=UpstreamResponse(
            200,
            b'OK',
            [
                ('Content-Type', 'text/html'),
                ('Set-Cookie', 'a=1; Path=/; Secure'),
                ('Set-Cookie', 'b=2; Path=/; Secure'),
            ],
            b'<html>ok</html>',
        )
    )
    app.links.add('192.0.2.10', 'http://example.com/', 443)
    request = FakeRequest()
    _run(request, app)
    values = [
        value.decode() for name, values in request.responseHeaders.items if name.lower() == b'set-cookie' for value in values
    ]
    assert len(values) == 2
    assert all('secure' not in item.lower() for item in values)


def test_upstream_failure_is_502() -> None:
    request = FakeRequest()
    _run(request, _app(error=ConnectionRefusedError('refused')))
    assert request.code == 502


def test_timeout_is_504() -> None:
    request = FakeRequest()
    _run(request, _app(error=ProxyTimeoutError('timeout')))
    assert request.code == 504


def test_unsupported_http_version_is_426() -> None:
    request = FakeRequest(clientproto=b'HTTP/2.0')
    _run(request, _app())
    assert request.code == 426


def test_head_omits_body() -> None:
    request = FakeRequest(method=b'HEAD')
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], b'secret')))
    assert request.code == 200
    assert request.body == b''


def _response_content_lengths(request: FakeRequest) -> list[str]:
    return [
        value.decode() for name, values in request.responseHeaders.items if name.lower() == b'content-length' for value in values
    ]


def test_head_preserves_upstream_content_length() -> None:
    request = FakeRequest(method=b'HEAD')
    _run(
        request,
        _app(
            response=UpstreamResponse(
                200,
                b'OK',
                [('Content-Type', 'text/html'), ('Content-Length', '4321')],
                b'',
            )
        ),
    )
    assert request.code == 200
    assert request.body == b''
    assert _response_content_lengths(request) == ['4321']


def test_no_body_status_has_no_synthesized_content_length() -> None:
    request = FakeRequest()
    _run(request, _app(response=UpstreamResponse(204, b'No Content', [('Content-Type', 'text/plain')], b'')))
    assert request.code == 204
    assert _response_content_lengths(request) == []


def test_malformed_https_url_in_body_passes_through() -> None:
    body = b'see https://example.com:abc/path and https://[::1/broken here'
    request = FakeRequest()
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], body)))
    assert request.code == 200
    assert request.body == body


def test_location_is_rewritten() -> None:
    app = _app(response=UpstreamResponse(302, b'Found', [('Location', 'https://secure.example/next')], b''))
    request = FakeRequest()
    _run(request, app)
    values = [value.decode() for name, values in request.responseHeaders.items if name.lower() == b'location' for value in values]
    assert values == ['http://secure.example/next']
    assert app.links.get('192.0.2.10', 'http://secure.example/next') == 443


def test_secure_relative_location_is_recorded() -> None:
    app = _app(response=UpstreamResponse(302, b'Found', [('Location', '/login#section')], b''))
    app.links.add('192.0.2.10', 'http://example.com/start', 443)
    request = FakeRequest(uri=b'/start')
    _run(request, app)
    values = [value.decode() for name, values in request.responseHeaders.items if name.lower() == b'location' for value in values]
    assert values == ['/login#section']
    assert app.links.get('192.0.2.10', 'http://example.com/login') == 443


def test_upgrade_header_is_426() -> None:
    request = FakeRequest(extra_headers=[(b'Upgrade', b'websocket')])
    _run(request, _app())
    assert request.code == 426


def test_invalid_host_is_400() -> None:
    request = FakeRequest(host='exa mple.com')
    _run(request, _app())
    assert request.code == 400


def test_ipv6_host_header_is_bracketed_upstream() -> None:
    target = UpstreamTarget(secure=False, hostname='2001:db8::1', port=8080, url='http://[2001:db8::1]:8080/')
    assert ('Host', '[2001:db8::1]:8080') in _outbound_headers([], target)

    default_port = UpstreamTarget(secure=True, hostname='2001:db8::1', port=443, url='https://[2001:db8::1]/')
    assert ('Host', '[2001:db8::1]') in _outbound_headers([], default_port)


def test_empty_content() -> None:
    request = FakeRequest()
    request.content = None
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], b'ok')))
    assert request.code == 200


def test_passthrough_malformed_html_gzip() -> None:
    request = FakeRequest()
    _run(
        request,
        _app(
            response=UpstreamResponse(
                200,
                b'OK',
                [('Content-Type', 'text/html'), ('Content-Encoding', 'gzip')],
                b'not-gzip',
            )
        ),
    )
    assert request.code == 200
    assert request.body == b'not-gzip'


def test_non_rewritable_sets_content_length() -> None:
    request = FakeRequest()
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'image/png')], b'\x89PNG')))
    assert request.code == 200
    assert _response_content_lengths(request) == ['4']


def test_large_passthrough_body_is_written_in_chunks() -> None:
    data = b'x' * 150_000
    body = ResponseBody(BytesIO(data), len(data))
    request = FakeRequest()
    _run(request, _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'image/png')], body)))
    assert request.body == data
    assert len(request.body_chunks) == 3


def test_streaming_producer_lifecycle() -> None:
    request = FakeRequest()
    stopped = _ResponseBodyProducer(request, ResponseBody(BytesIO(b'data'), 4))
    stopped.pauseProducing()
    stopped.stopProducing()
    assert stopped.finished.called

    closed_body = ResponseBody(BytesIO(b'data'), 4)
    closed_body.close()
    failed = _ResponseBodyProducer(request, closed_body)
    failures = []
    failed.finished.addErrback(failures.append)
    failed.resumeProducing()
    assert failures


def test_send_error_swallows_write_failure() -> None:
    class BoomRequest(FakeRequest):
        @override
        def setResponseCode(self, code: int, message: bytes | None = None) -> None:
            del code, message
            raise RuntimeError('cannot write')

    _run(BoomRequest(host=None), _app())


def test_unchanged_gzip_html_keeps_original_bytes() -> None:
    html = b'<html>plain</html>'
    encoded = gzip.compress(html)
    request = FakeRequest()
    _run(
        request,
        _app(
            response=UpstreamResponse(
                200,
                b'OK',
                [('Content-Type', 'text/html'), ('Content-Encoding', 'gzip'), ('ETag', '"abc"')],
                encoded,
            )
        ),
    )
    assert request.body == encoded
    etags = [value.decode() for name, values in request.responseHeaders.items if name.lower() == b'etag' for value in values]
    assert etags == ['"abc"']


def test_secure_page_records_relative_links() -> None:
    app = _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/html')], b'<a href="next">x</a>'))
    app.links.add('192.0.2.10', 'http://example.com/app', 443)
    request = FakeRequest(uri=b'/app')
    _run(request, app)
    assert app.links.get('192.0.2.10', 'http://example.com/next') == 443


def test_secure_page_respects_html_base_before_rewriting() -> None:
    body = b'<base href="https://example.com/other/"><a href="next#section">x</a>'
    app = _app(response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/html')], body))
    app.links.add('192.0.2.10', 'http://example.com/app/page', 443)
    request = FakeRequest(uri=b'/app/page')
    _run(request, app)
    assert b'<base href="http://example.com/other/">' in request.body
    assert app.links.get('192.0.2.10', 'http://example.com/other/next') == 443


def test_duplicate_non_cookie_headers() -> None:
    request = FakeRequest()
    _run(
        request,
        _app(
            response=UpstreamResponse(
                200,
                b'OK',
                [('Content-Type', 'text/plain'), ('X-Custom', 'a'), ('X-Custom', 'b')],
                b'ok',
            )
        ),
    )
    values = [value.decode() for name, values in request.responseHeaders.items if name.lower() == b'x-custom' for value in values]
    assert values == ['a', 'b']


def test_traffic_log_request(tmp_path: Path) -> None:
    path = tmp_path / 'traffic.log'
    app = _app(
        response=UpstreamResponse(200, b'OK', [('Content-Type', 'text/plain')], b'ok'),
        traffic=TrafficLog('all', path),
    )
    request = FakeRequest()
    _run(request, app)
    app.traffic.close()
    text = path.read_text(encoding='utf-8')
    assert 'request' in text
