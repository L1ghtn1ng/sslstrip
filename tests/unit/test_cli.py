"""CLI validation and version reporting."""

from pathlib import Path

import pytest

from sslstrip.cli import main
from sslstrip.config import ConfigError, parse_config


def test_version_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(['--version']) == 0
    assert '5.0.0' in capsys.readouterr().out


def test_short_version_is_handled_by_argparse(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(['-V']) == 0
    assert capsys.readouterr().out.strip() == '5.0.0'


def test_missing_command_is_error() -> None:
    assert main([]) == 2


def test_manage_network_requires_interface_and_target() -> None:
    with pytest.raises(ConfigError, match='--interface'):
        parse_config(['run', '--manage-network', '--target', '192.0.2.8'])
    with pytest.raises(ConfigError, match='--target'):
        parse_config(['run', '--manage-network', '--interface', 'eth0'])


def test_invalid_target() -> None:
    with pytest.raises(ConfigError, match='IPv4'):
        parse_config(['run', '--target', 'not-an-ip'])


def test_traffic_log_requires_file() -> None:
    with pytest.raises(ConfigError, match='traffic-log-file'):
        parse_config(['run', '--traffic-log', 'all'])
    with pytest.raises(ConfigError, match='traffic-log'):
        parse_config(['run', '--traffic-log-file', '/tmp/t.log'])


def test_listen_port_range() -> None:
    with pytest.raises(ConfigError, match='listen port'):
        parse_config(['run', '--listen-port', '0'])


def test_parse_run_defaults() -> None:
    parsed = parse_config(['run'])
    assert parsed.command == 'run'
    assert parsed.listen_port == 10000
    assert parsed.listen_host == '127.0.0.1'


def test_help_is_success() -> None:
    assert main(['-h']) == 0
    assert main(['run', '-h']) == 0


def test_unknown_flag_is_error() -> None:
    assert main(['run', '--no-such-flag']) == 2


def test_doctor_cli(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(['doctor', '--listen-port', '18765'])
    assert code in {0, 1}
    output = capsys.readouterr().out
    assert 'python' in output


def test_traffic_log_symlink_is_error(tmp_path: Path) -> None:
    target = tmp_path / 'real'
    target.write_text('x', encoding='utf-8')
    link = tmp_path / 'link.log'
    link.symlink_to(target)
    assert main(['run', '--traffic-log', 'all', '--traffic-log-file', str(link)]) == 2


def test_version_via_parse() -> None:
    with pytest.raises(SystemExit) as exc_info:
        parse_config(['--version'])
    assert exc_info.value.code == 0


def test_invalid_listen_port_via_main() -> None:
    assert main(['run', '--listen-port', '0']) == 2


def test_cleanup_without_root(tmp_path: Path) -> None:
    assert main(['cleanup', '--state-dir', str(tmp_path)]) == 2


def test_managed_without_root() -> None:
    assert main(['run', '--manage-network', '--interface', 'lo', '--target', '127.0.0.1']) == 2


def test_run_starts_proxy_and_reactor(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr('sslstrip.cli.start_proxy', lambda _reactor, _config: calls.append('proxy'))
    monkeypatch.setattr('sslstrip.cli.run_reactor', lambda _reactor: calls.append('reactor'))
    assert main(['run']) == 0
    assert calls == ['proxy', 'reactor']


def test_keyboard_interrupt_returns_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(_reactor: object, _config: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr('sslstrip.cli.start_proxy', interrupt)
    assert main(['run']) == 130
