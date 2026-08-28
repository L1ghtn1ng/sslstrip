"""Cookie Secure-flag stripping and optional first-request session expiration."""

from dataclasses import dataclass, field

from sslstrip.urls import InvalidAuthorityError, split_host_header


def strip_secure_flag(set_cookie: str) -> str:
    """Remove a ``Secure`` attribute from a Set-Cookie header value."""
    parts = [part.strip() for part in set_cookie.split(';')]
    kept = [part for part in parts if part.lower() != 'secure']
    return '; '.join(kept)


@dataclass
class SessionExpirer:
    """Expire cookies on the first request from a client to a given host."""

    enabled: bool = False
    _cleaned: set[tuple[str, str]] = field(default_factory=set)

    def should_expire(self, method: str, client: str, host: str, cookie_header: str | None) -> bool:
        """Return True when this request should receive expiration Set-Cookie headers."""
        if not self.enabled:
            return False
        if method.upper() == 'POST':
            return False
        if not cookie_header:
            return False
        return (client, _cookie_domain(host)) not in self._cleaned

    def expire_headers(self, client: str, host: str, path: str, cookie_header: str) -> list[str]:
        """Build expiration Set-Cookie values and mark the client/host as cleaned."""
        domain = _cookie_domain(host)
        self._cleaned.add((client, domain))
        headers: list[str] = []
        for raw_cookie in cookie_header.split(';'):
            name = raw_cookie.split('=', 1)[0].strip()
            if not name:
                continue
            headers.extend(_expire_strings(name, host, domain, path))
        return headers


def _hostname(host: str) -> str:
    try:
        hostname, _port = split_host_header(host)
    except InvalidAuthorityError:
        hostname = host.split('%', 1)[0]
    return hostname


def _cookie_domain(host: str) -> str:
    hostname = _hostname(host)
    labels = hostname.split('.')
    if len(labels) >= 2:
        return '.' + labels[-2] + '.' + labels[-1]
    return hostname


def _expire_strings(name: str, host: str, domain: str, path: str) -> list[str]:
    hostname = _hostname(host)
    path_list = path.split('/')
    expire_format = '{name}=EXPIRED; Path={path}; Domain={domain}; Expires=Mon, 01-Jan-1990 00:00:00 GMT'
    result = [
        expire_format.format(name=name, path='/', domain=domain),
        expire_format.format(name=name, path='/', domain=hostname),
    ]
    if len(path_list) > 2:
        sub_path = '/' + path_list[1]
        result.append(expire_format.format(name=name, path=sub_path, domain=domain))
        result.append(expire_format.format(name=name, path=sub_path, domain=hostname))
    return result
