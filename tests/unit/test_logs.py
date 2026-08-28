"""Traffic log permissions, symlink refusal, and mode gating."""

from pathlib import Path

import pytest

from sslstrip.logs import TrafficLog, TrafficLogError, open_traffic_log


def test_mode_off_never_writes(tmp_path: Path) -> None:
    log = TrafficLog('off', None)
    assert not log.enabled_for(method='POST', secure=True)
    log.close()


def test_post_mode_only_posts(tmp_path: Path) -> None:
    path = tmp_path / 'traffic.log'
    log = TrafficLog('post', path)
    assert log.enabled_for(method='POST', secure=False)
    assert not log.enabled_for(method='GET', secure=True)
    log.write(direction='request', method='POST', url='http://x/', secure=False, headers=[('Host', 'x')], body=b'secret=1')
    log.close()
    text = path.read_text(encoding='utf-8')
    assert 'secret=1' in text
    assert oct(path.stat().st_mode & 0o777) == '0o600'


def test_secure_and_all_modes(tmp_path: Path) -> None:
    path = tmp_path / 't.log'
    log = TrafficLog('secure', path)
    assert log.enabled_for(method='GET', secure=True)
    assert not log.enabled_for(method='GET', secure=False)
    log.close()
    log = TrafficLog('all', path)
    assert log.enabled_for(method='GET', secure=False)
    log.close()


def test_symlink_refused(tmp_path: Path) -> None:
    target = tmp_path / 'real'
    target.write_text('x', encoding='utf-8')
    link = tmp_path / 'link.log'
    link.symlink_to(target)
    with pytest.raises(TrafficLogError, match='symlink'):
        open_traffic_log(link)


def test_directory_refused(tmp_path: Path) -> None:
    directory = tmp_path / 'dir'
    directory.mkdir()
    with pytest.raises(TrafficLogError, match='regular file'):
        open_traffic_log(directory)


def test_configure_logging_levels() -> None:
    from sslstrip.logs import configure_logging

    configure_logging(0)
    configure_logging(1)
    configure_logging(2)


def test_traffic_log_requires_file() -> None:
    with pytest.raises(TrafficLogError, match='traffic-log-file'):
        TrafficLog('all', None)


def test_write_skipped_when_disabled(tmp_path: Path) -> None:
    path = tmp_path / 't.log'
    log = TrafficLog('post', path)
    log.write(direction='request', method='GET', url='http://x/', secure=False, headers={'Host': 'x'}, body=b'nope')
    log.close()
    assert path.read_text(encoding='utf-8') == ''


def test_streamed_body_preserves_split_utf8(tmp_path: Path) -> None:
    path = tmp_path / 'stream.log'
    log = TrafficLog('all', path)
    log.write(
        direction='response',
        method='GET',
        url='http://x/',
        secure=False,
        headers=[],
        body=iter([b'caf\xc3', b'\xa9']),
    )
    log.close()
    assert 'café' in path.read_text(encoding='utf-8')
