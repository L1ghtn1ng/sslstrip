"""Cookie Secure stripping and first-request expiration."""

from sslstrip.cookies import SessionExpirer, strip_secure_flag


def test_strip_secure_anywhere() -> None:
    original = 'sid=abc; Path=/; Secure; HttpOnly'
    stripped = strip_secure_flag(original)
    assert 'secure' not in stripped.lower()
    assert 'sid=abc' in stripped
    assert 'HttpOnly' in stripped


def test_first_request_expires_then_passes() -> None:
    cleaner = SessionExpirer(enabled=True)
    assert cleaner.should_expire('GET', '1.2.3.4', 'mail.example.com', 'sid=1')
    headers = cleaner.expire_headers('1.2.3.4', 'mail.example.com', '/inbox', 'sid=1')
    assert len(headers) >= 2
    assert all('sid=EXPIRED' in item for item in headers)
    assert not cleaner.should_expire('GET', '1.2.3.4', 'mail.example.com', 'sid=1')


def test_post_never_expires() -> None:
    cleaner = SessionExpirer(enabled=True)
    assert not cleaner.should_expire('POST', '1.2.3.4', 'example.com', 'sid=1')


def test_disabled_never_expires() -> None:
    cleaner = SessionExpirer(enabled=False)
    assert not cleaner.should_expire('GET', '1.2.3.4', 'example.com', 'sid=1')


def test_no_cookie_header_skips() -> None:
    cleaner = SessionExpirer(enabled=True)
    assert not cleaner.should_expire('GET', '1.2.3.4', 'example.com', None)
    assert not cleaner.should_expire('GET', '1.2.3.4', 'example.com', '')


def test_expire_nested_path_and_empty_name() -> None:
    cleaner = SessionExpirer(enabled=True)
    headers = cleaner.expire_headers('1.2.3.4', 'example.com:80', '/inbox/msg', '; sid=1; =bad')
    assert any('Path=/inbox' in item for item in headers)
    assert all('=bad' not in item for item in headers)


def test_ipv6_cookie_domain() -> None:
    cleaner = SessionExpirer(enabled=True)
    headers = cleaner.expire_headers('1.2.3.4', '[::1]:8080', '/', 'sid=1')
    assert any('Domain=::1' in item for item in headers)
    assert all('Domain=[' not in item for item in headers)


def test_invalid_host_fallback() -> None:
    cleaner = SessionExpirer(enabled=True)
    headers = cleaner.expire_headers('1.2.3.4', 'not a host', '/', 'sid=1')
    assert any('sid=EXPIRED' in item for item in headers)
