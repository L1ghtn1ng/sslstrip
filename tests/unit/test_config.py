"""Config validation helpers."""

import pytest

from sslstrip.config import ConfigError, interface_exists, interface_ipv4, parse_run_as, validate_interface_name


def test_interface_name_rejects_metacharacters() -> None:
    with pytest.raises(ConfigError):
        validate_interface_name('eth0/foo')
    with pytest.raises(ConfigError):
        validate_interface_name('eth 0')
    with pytest.raises(ConfigError):
        validate_interface_name('')
    with pytest.raises(ConfigError):
        validate_interface_name('.')
    with pytest.raises(ConfigError):
        validate_interface_name('a' * 20)
    validate_interface_name('dummy0')
    validate_interface_name('enp0s3')


def test_loopback_interface() -> None:
    assert interface_exists('lo')
    assert str(interface_ipv4('lo')) == '127.0.0.1'
    with pytest.raises(ConfigError, match='unknown interface'):
        interface_ipv4('nosuch0')


def test_parse_run_as() -> None:
    uid, gid = parse_run_as('0')
    assert uid == 0
    assert isinstance(gid, int)
    with pytest.raises(ConfigError, match='unknown user'):
        parse_run_as('this-user-does-not-exist-sslstrip')
    with pytest.raises(ConfigError, match='unknown group'):
        parse_run_as('0:this-group-does-not-exist-sslstrip')


def test_parse_managed_run() -> None:
    from sslstrip.config import parse_config

    parsed = parse_config(['run', '--manage-network', '--interface', 'lo', '--target', '127.0.0.1', '--run-as', '0'])
    assert parsed != 'version'
    assert parsed.manage_network
    assert parsed.interface == 'lo'


def test_invalid_limits() -> None:
    from sslstrip.config import parse_config

    with pytest.raises(ConfigError, match='max-body-size'):
        parse_config(['run', '--max-body-size', '0'])
    with pytest.raises(ConfigError, match='timeouts'):
        parse_config(['run', '--connect-timeout', '0'])
    with pytest.raises(ConfigError, match='ca-file'):
        parse_config(['run', '--ca-file', '/no/such/ca.pem'])
