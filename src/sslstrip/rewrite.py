"""Rewrite HTTPS references and discover relative links on secure pages."""

import re
from html import unescape
from html.parser import HTMLParser
from typing import override
from urllib.parse import urljoin

from sslstrip.links import SecureLinkStore
from sslstrip.urls import InvalidAuthorityError, https_url_to_http

HTTPS_URL_RE = re.compile(
    r'https://[^\s"\'<>\\)]+',
    re.IGNORECASE,
)
CSS_URL_RE = re.compile(
    r'url\(\s*([\'"]?)([^\'")]+)\1\s*\)',
    re.IGNORECASE,
)
CSS_IMPORT_RE = re.compile(r'@import\s+([\'"])(.*?)\1', re.IGNORECASE)

REWRITABLE_TYPES = frozenset(
    {
        'text/html',
        'application/xhtml+xml',
        'text/css',
        'text/plain',
        'text/javascript',
        'application/javascript',
        'application/xml',
        'text/xml',
    }
)


def is_rewritable(content_type: str | None) -> bool:
    """Return True if the media type is eligible for HTTPS rewriting."""
    if content_type is None:
        return False
    media = content_type.split(';', 1)[0].strip().lower()
    return media in REWRITABLE_TYPES


def parse_charset(content_type: str | None) -> str:
    """Extract a charset from Content-Type, defaulting to UTF-8."""
    if content_type is None:
        return 'utf-8'
    for part in content_type.split(';')[1:]:
        stripped = part.strip()
        if stripped.lower().startswith('charset='):
            value = stripped.split('=', 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    return 'utf-8'


def decode_text(data: bytes, content_type: str | None) -> tuple[str, str]:
    """Decode response bytes using the declared charset."""
    charset = parse_charset(content_type)
    try:
        return data.decode(charset), charset
    except LookupError:
        return data.decode('utf-8', errors='surrogateescape'), 'utf-8'
    except UnicodeDecodeError:
        return data.decode(charset, errors='surrogateescape'), charset


def encode_text(text: str, charset: str) -> bytes:
    """Encode rewritten text back to the original charset."""
    try:
        return text.encode(charset)
    except LookupError:
        return text.encode('utf-8', errors='surrogateescape')
    except UnicodeEncodeError:
        return text.encode(charset, errors='surrogateescape')


def rewrite_https_references(text: str, client: str, store: SecureLinkStore) -> str:
    """Replace ``https://`` URLs with ``http://`` and record secure targets."""

    def _replace(match: re.Match[str]) -> str:
        original = match.group(0)
        trimmed = original.rstrip('.,;:)]}')
        suffix = original[len(trimmed) :]
        try:
            http_url, port = https_url_to_http(trimmed)
        except InvalidAuthorityError:
            return original
        store.add(client, unescape(http_url), port)
        return http_url + suffix

    return HTTPS_URL_RE.sub(_replace, text)


def discover_relative_links(
    text: str,
    *,
    content_type: str,
    https_base: str,
    client: str,
    store: SecureLinkStore,
) -> None:
    """Record relative HTML/CSS links from a secure upstream page."""
    media = content_type.split(';', 1)[0].strip().lower()
    if media in {'text/html', 'application/xhtml+xml'}:
        links, base_href = _html_links(text)
        resolved_base = urljoin(https_base, base_href) if base_href is not None else https_base
        for link in links:
            _record_relative(link, https_base=resolved_base, client=client, store=store)
        return
    if media == 'text/css':
        for link in _css_links(text):
            _record_relative(link, https_base=https_base, client=client, store=store)


def rewrite_location(
    value: str,
    client: str,
    store: SecureLinkStore,
    *,
    https_base: str | None = None,
) -> str:
    """Rewrite absolute HTTPS redirects and record secure relative redirects."""
    stripped = value.strip()
    if stripped.lower().startswith('https://'):
        return rewrite_https_references(stripped, client, store)
    if https_base is not None:
        _record_relative(stripped, https_base=https_base, client=client, store=store)
    return value


def _record_relative(link: str, *, https_base: str, client: str, store: SecureLinkStore) -> None:
    if link.startswith('#') or link.lower().startswith('javascript:') or link.lower().startswith('data:'):
        return
    if link.lower().startswith('https://'):
        try:
            http_url, port = https_url_to_http(link)
        except InvalidAuthorityError:
            return
        store.add(client, http_url, port)
        return
    if link.lower().startswith('http://'):
        return
    absolute = urljoin(https_base, link)
    if not absolute.lower().startswith('https://'):
        return
    try:
        http_url, port = https_url_to_http(absolute)
    except InvalidAuthorityError:
        return
    store.add(client, http_url, port)


def _html_links(text: str) -> tuple[list[str], str | None]:
    parser = _LinkParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return parser.links, parser.base_href
    return parser.links, parser.base_href


def _css_links(text: str) -> list[str]:
    urls = [str(match.group(2)).strip() for match in CSS_URL_RE.finditer(text)]
    imports = [str(match.group(2)).strip() for match in CSS_IMPORT_RE.finditer(text)]
    return urls + imports


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.base_href: str | None = None

    @override
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == 'base' and self.base_href is None:
            self.base_href = next((value for name, value in attrs if name.lower() == 'href' and value), None)
            return
        interesting = {'href', 'src', 'action'}
        for name, value in attrs:
            if name.lower() in interesting and value:
                self.links.append(value)
