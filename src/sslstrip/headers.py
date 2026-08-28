"""Hop-by-hop filtering and multi-value header preservation."""

from collections.abc import Iterable, Sequence

HOP_BY_HOP = frozenset(
    {
        'connection',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'proxy-connection',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    }
)

HOP_BY_HOP_REQUEST_EXTRAS = frozenset(
    {
        'if-match',
        'if-modified-since',
        'if-none-match',
        'if-range',
        'if-unmodified-since',
    }
)

VALIDATOR_RESPONSE_HEADERS = frozenset(
    {
        'etag',
        'content-md5',
        'digest',
        'last-modified',
    }
)

HeaderPair = tuple[str, str]


def filter_request_headers(headers: Sequence[HeaderPair]) -> list[HeaderPair]:
    """Drop hop-by-hop headers, connection tokens, and cache validators."""
    extra = _connection_tokens(headers)
    skip = {name.lower() for name in HOP_BY_HOP | HOP_BY_HOP_REQUEST_EXTRAS | extra}
    skip.add('accept-encoding')
    skip.add('host')
    return [(name, value) for name, value in headers if name.lower() not in skip]


def filter_response_headers(headers: Sequence[HeaderPair], *, body_changed: bool) -> list[HeaderPair]:
    """Drop hop-by-hop headers; drop validators and Content-Length when the body changed."""
    extra = _connection_tokens(headers)
    skip = {name.lower() for name in HOP_BY_HOP | extra}
    if body_changed:
        skip.add('content-length')
        skip.update(VALIDATOR_RESPONSE_HEADERS)
    return [(name, value) for name, value in headers if name.lower() not in skip]


def header_values(headers: Sequence[HeaderPair], name: str) -> list[str]:
    """Return all values for ``name`` (case-insensitive), preserving order."""
    needle = name.lower()
    return [value for header_name, value in headers if header_name.lower() == needle]


def first_header(headers: Sequence[HeaderPair], name: str) -> str | None:
    """Return the first value for ``name``, or None."""
    values = header_values(headers, name)
    if not values:
        return None
    return values[0]


def replace_header(headers: Sequence[HeaderPair], name: str, value: str) -> list[HeaderPair]:
    """Remove existing values for ``name`` and append a single replacement."""
    needle = name.lower()
    kept = [(header_name, header_value) for header_name, header_value in headers if header_name.lower() != needle]
    kept.append((name, value))
    return kept


def drop_headers(headers: Sequence[HeaderPair], names: Iterable[str]) -> list[HeaderPair]:
    """Return a copy without the named headers."""
    skip = {name.lower() for name in names}
    return [(header_name, value) for header_name, value in headers if header_name.lower() not in skip]


def _connection_tokens(headers: Sequence[HeaderPair]) -> set[str]:
    tokens: set[str] = set()
    for value in header_values(headers, 'connection'):
        for token in value.split(','):
            cleaned = token.strip().lower()
            if cleaned:
                tokens.add(cleaned)
    return tokens
