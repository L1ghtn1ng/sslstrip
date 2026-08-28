"""Doctor checks are read-only and report structured results."""

import os
from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.fakes import sample_config

from sslstrip.doctor import (
    _check_ca_file,
    _check_dependency,
    _check_interface,
    _check_nft,
    _check_port,
    _check_privilege,
    _check_state_dir,
    format_report,
    run_doctor,
)


def test_doctor_python_and_dependencies() -> None:
    results = run_doctor(sample_config(command='doctor', listen_port=18764))
    names = {item.name: item for item in results}
    assert names['python'].ok
    assert names['twisted'].ok
    assert names['brotli'].ok
    assert names['compression.zstd'].ok
    assert names['ca-file'].ok
    report = format_report(results)
    assert 'python' in report
    assert 'ok' in report


def test_doctor_missing_interface() -> None:
    results = run_doctor(sample_config(command='doctor', interface='no-such-iface-sslstrip', listen_port=18764))
    names = {item.name: item for item in results}
    assert not names['interface'].ok


def test_doctor_target_and_state(tmp_path: Path) -> None:
    results = run_doctor(
        sample_config(
            command='doctor',
            target=IPv4Address('192.0.2.8'),
            state_dir=tmp_path / 'state',
            listen_port=0,
        )
    )
    names = {item.name: item for item in results}
    assert names['target'].ok
    assert names['state-dir'].ok


def test_doctor_managed_checks_require_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr('sslstrip.doctor.os.geteuid', lambda: 1000)
    config = sample_config(command='doctor', interface='dummy0', target=IPv4Address('192.0.2.8'))
    result = _check_privilege(config)
    assert not result.ok
    assert result.detail == 'euid=1000'


def test_doctor_bad_ca_file(tmp_path: Path) -> None:
    ca = tmp_path / 'ca.pem'
    ca.write_text('not a cert', encoding='utf-8')
    results = run_doctor(sample_config(command='doctor', ca_file=ca, listen_port=0))
    names = {item.name: item for item in results}
    assert not names['ca-file'].ok


def test_doctor_state_dir_is_file(tmp_path: Path) -> None:
    path = tmp_path / 'notdir'
    path.write_text('x', encoding='utf-8')
    results = run_doctor(sample_config(command='doctor', state_dir=path, listen_port=0))
    names = {item.name: item for item in results}
    assert not names['state-dir'].ok


def test_doctor_validates_existing_state_directory_mode(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    assert _check_state_dir(sample_config(command='doctor', state_dir=tmp_path)).ok
    tmp_path.chmod(0o755)
    result = _check_state_dir(sample_config(command='doctor', state_dir=tmp_path))
    assert not result.ok
    assert '0700' in result.detail


def test_doctor_rejects_non_directory_ancestor(tmp_path: Path) -> None:
    parent = tmp_path / 'file'
    parent.write_text('x', encoding='utf-8')
    result = _check_state_dir(sample_config(command='doctor', state_dir=parent / 'state'))
    assert not result.ok
    assert 'not a directory' in result.detail


def test_doctor_rejects_wrong_owner_state_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    actual_uid = os.geteuid()
    monkeypatch.setattr('sslstrip.doctor.os.geteuid', lambda: actual_uid + 1)
    result = _check_state_dir(sample_config(command='doctor', state_dir=tmp_path))
    assert not result.ok
    assert 'owner' in result.detail


def test_doctor_rejects_unsafe_state_directory_ancestor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    actual_uid = os.geteuid()
    monkeypatch.setattr('sslstrip.doctor.os.geteuid', lambda: actual_uid + 1)
    result = _check_state_dir(sample_config(command='doctor', state_dir=state))
    assert not result.ok
    assert 'unsafe owner' in result.detail


def test_doctor_missing_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(_name: str) -> None:
        raise ImportError('not installed')

    monkeypatch.setattr('sslstrip.doctor.importlib.import_module', missing)
    assert not _check_dependency('optional').ok


def test_doctor_interface_validation_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _check_interface(sample_config(command='doctor', interface='..')).ok

    config = sample_config(command='doctor', interface='dummy0')
    monkeypatch.setattr('sslstrip.doctor.interface_exists', lambda _name: False)
    assert not _check_interface(config).ok

    monkeypatch.setattr('sslstrip.doctor.interface_exists', lambda _name: True)
    monkeypatch.setattr('sslstrip.doctor.interface_ipv4', lambda _name: (_ for _ in ()).throw(OSError('no address')))
    assert not _check_interface(config).ok


def test_doctor_nft_failure_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = sample_config(command='doctor', nft_executable='/no/such/nft')
    assert not _check_nft(missing).ok

    monkeypatch.setattr('sslstrip.doctor.shutil.which', lambda _name: '/usr/sbin/nft')
    monkeypatch.setattr(
        'sslstrip.doctor.run_nft',
        lambda *_args: SimpleNamespace(returncode=1, stdout=b'', stderr=b'permission denied'),
    )
    result = _check_nft(sample_config(command='doctor'))
    assert not result.ok
    assert result.detail == 'permission denied'


def test_doctor_port_bind_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Socket:
        def setsockopt(self, *_args: object) -> None:
            return None

        def bind(self, _address: object) -> None:
            raise OSError('in use')

        def close(self) -> None:
            return None

    monkeypatch.setattr('sslstrip.doctor.socket.socket', lambda *_args: Socket())
    assert not _check_port(sample_config(command='doctor')).ok


def test_doctor_state_and_ca_file_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    parent = tmp_path / 'parent'
    parent.mkdir()
    monkeypatch.setattr('sslstrip.doctor.os.access', lambda *_args: False)
    assert not _check_state_dir(sample_config(command='doctor', state_dir=parent / 'state')).ok
    assert _check_state_dir(sample_config(command='doctor', state_dir=tmp_path / 'missing' / 'state')).ok

    missing_ca = tmp_path / 'missing.pem'
    assert not _check_ca_file(sample_config(command='doctor', ca_file=missing_ca)).ok
    valid_ca = tmp_path / 'ca.pem'
    valid_ca.write_text('-----BEGIN CERTIFICATE-----\n', encoding='utf-8')
    assert _check_ca_file(sample_config(command='doctor', ca_file=valid_ca)).ok
