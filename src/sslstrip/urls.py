"""URL normalization for stripped HTTP requests and HTTPS origins."""

from ipaddress import AddressValueError, IPv4Address, IPv6Address
from urllib.parse import urlsplit, urlunsplit

_URI_SCHEME_HTTP = 'http://'
_URI_SCHEME_HTTPS = 'https://'


class InvalidAuthorityError(ValueError):
    """The Host header or URL authority is not a usable HTTP authority."""


def decode_request_uri(uri: bytes) -> str:
    """Decode a request-target using latin-1, matching HTTP/1.1 bytes."""
    return uri.decode('latin-1')


def origin_form_path(uri: str) -> str:
    """Return origin-form ``/path?query`` from origin-form or absolute-form."""
    stripped = uri.strip()
    lower = stripped.lower()
    if lower.startswith(_URI_SCHEME_HTTP) or lower.startswith(_URI_SCHEME_HTTPS):
        parts = urlsplit(stripped)
        path = parts.path if parts.path else '/'
        if parts.query:
            return f'{path}?{parts.query}'
        return path
    if not stripped.startswith('/'):
        return f'/{stripped}'
    return stripped


def split_host_header(host_header: str) -> tuple[str, int | None]:
    """Split a Host header into hostname and optional port.

    Raises:
        InvalidAuthorityError: If the header is empty or malformed.
    """
    value = host_header.strip()
    if not value or any(ch in value for ch in ' \t\r\n\x00'):
        raise InvalidAuthorityError('invalid Host header')
    hostname: str
    port: int | None
    if value.startswith('['):
        end = value.find(']')
        if end == -1:
            raise InvalidAuthorityError('invalid IPv6 Host header')
        hostname = value[1:end]
        rest = value[end + 1 :]
        if rest == '':
            port = None
        elif rest.startswith(':'):
            port = _parse_port(rest[1:])
        else:
            raise InvalidAuthorityError('invalid IPv6 Host header')
        _validate_ipv6(hostname)
        return hostname, port
    if value.count(':') == 1:
        host_part, port_part = value.rsplit(':', 1)
        if host_part == '':
            raise InvalidAuthorityError('invalid Host header')
        hostname = host_part
        port = _parse_port(port_part)
    else:
        hostname = value
        port = None
    _validate_hostname_or_ipv4(hostname)
    return hostname, port


def canonical_http_url(hostname: str, port: int | None, path: str) -> str:
    """Build the HTTP URL key used in the secure-link store."""
    netloc = _format_netloc(hostname, _omit_default_port(port, default=80))
    normalized_path = path if path.startswith('/') else f'/{path}'
    return urlunsplit(('http', netloc, normalized_path.split('?', 1)[0], _query(normalized_path), ''))


def https_url_to_http(url: str) -> tuple[str, int]:
    """Rewrite an ``https://`` URL to ``http://`` and return ``(http_url, https_port)``.

    Default port 443 is omitted from the visible HTTP URL. Non-default HTTPS ports
    are retained in the HTTP URL so the client Host header round-trips.
    """
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise InvalidAuthorityError('invalid https URL') from exc
    if parts.scheme.lower() != 'https':
        raise InvalidAuthorityError('not an https URL')
    hostname = parts.hostname
    if hostname is None or hostname == '':
        raise InvalidAuthorityError('https URL missing host')
    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise InvalidAuthorityError('invalid https URL port') from exc
    https_port = explicit_port if explicit_port is not None else 443
    visible_port = None if https_port == 443 else https_port
    netloc = _format_netloc(hostname, visible_port)
    path = parts.path if parts.path else '/'
    http_url = urlunsplit(('http', netloc, path, parts.query, parts.fragment))
    if url.endswith('#') and not http_url.endswith('#'):
        http_url += '#'
    return http_url, https_port


def request_http_url(host_header: str, uri: bytes) -> tuple[str, str, int | None, str]:
    """Return ``(canonical_http_url, hostname, port, path)`` for a client request."""
    hostname, port = split_host_header(host_header)
    path = origin_form_path(decode_request_uri(uri))
    return canonical_http_url(hostname, port, path), hostname, port, path


def upstream_url(*, secure: bool, hostname: str, port: int, path: str) -> str:
    """Build the absolute URL the Agent should request."""
    scheme = 'https' if secure else 'http'
    default = 443 if secure else 80
    visible = None if port == default else port
    netloc = _format_netloc(hostname, visible)
    normalized_path = path if path.startswith('/') else f'/{path}'
    query = _query(normalized_path)
    path_only = normalized_path.split('?', 1)[0]
    return urlunsplit((scheme, netloc, path_only, query, ''))


def _query(path: str) -> str:
    if '?' not in path:
        return ''
    return path.split('?', 1)[1]


def _parse_port(raw: str) -> int:
    if raw == '' or not raw.isdigit():
        raise InvalidAuthorityError('invalid port')
    port = int(raw)
    if port < 1 or port > 65535:
        raise InvalidAuthorityError('invalid port')
    return port


def _omit_default_port(port: int | None, default: int) -> int | None:
    if port is None or port == default:
        return None
    return port


def _format_netloc(hostname: str, port: int | None) -> str:
    host = hostname
    try:
        IPv6Address(hostname)
        host = f'[{hostname}]'
    except AddressValueError:
        host = hostname
    if port is None:
        return host
    return f'{host}:{port}'


def _validate_ipv6(hostname: str) -> None:
    try:
        IPv6Address(hostname)
    except AddressValueError as exc:
        raise InvalidAuthorityError('invalid IPv6 address') from exc


def _validate_hostname_or_ipv4(hostname: str) -> None:
    if hostname == '':
        raise InvalidAuthorityError('empty host')
    try:
        IPv4Address(hostname)
        return
    except AddressValueError:
        pass
    if hostname.lower() == 'localhost':
        return
    labels = hostname.split('.')
    if any(label == '' for label in labels):
        raise InvalidAuthorityError('invalid hostname')
    for label in labels:
        if len(label) > 63 or not all(ch.isalnum() or ch == '-' for ch in label):
            raise InvalidAuthorityError('invalid hostname')
        if label.startswith('-') or label.endswith('-'):
            raise InvalidAuthorityError('invalid hostname')
