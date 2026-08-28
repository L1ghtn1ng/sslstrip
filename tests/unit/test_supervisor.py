"""Supervisor locking, privilege, ownership, forwarding, and cleanup."""

import json
import os
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address
from pathlib import Path
from types import FrameType
from typing import cast

import pytest
from tests.fakes import sample_config

from sslstrip.config import AppConfig, ConfigError, parse_run_as
from sslstrip.nftables import NftablesError, delete_table_payload
from sslstrip.supervisor import (
    ManagedState,
    StateDirectory,
    SupervisorHooks,
    WorkerProcess,
    _process_start_time,
    _safe_delete_table,
    _safe_stop_spawned_worker,
    _stop_recorded_worker,
    acquire_lock,
    cleanup_managed,
    default_hooks,
    prepare_state_dir,
    read_state,
    remove_state,
    run_managed,
    spawn_worker_process,
    worker_command,
    write_state,
)


class _FakeProc:
    def __init__(self) -> None:
        self.pid: int | None = 4242
        self.signals: list[int] = []

    def send_signal(self, signum: int) -> None:
        self.signals.append(signum)

    def wait(self) -> int:
        return 0


@dataclass
class _HookLog:
    forward: str = '0'
    writes: list[str] = field(default_factory=list)
    nft: list[bytes] = field(default_factory=list)
    spawned: tuple[int, int] | None = None
    signals: list[int] = field(default_factory=list)
    table: dict[str, object] | None = None
    state_at_spawn: bool = False
    state_at_forward: bool = False
    terminated_pids: list[int] = field(default_factory=list)


def _hooks(
    tmp_path: Path,
    *,
    euid: int = 0,
    sudo: tuple[int, int] | None = (1000, 1000),
    existing_table: dict[str, object] | None = None,
    wait_code: int = 0,
    delete_error: bool = False,
    deletion_sticks: bool = False,
) -> tuple[SupervisorHooks, _HookLog]:
    log = _HookLog(table=existing_table)
    proc = _FakeProc()
    process_starts = {4242: 12345}

    def read_forward() -> str:
        return log.forward

    def write_forward(value: str) -> None:
        log.writes.append(value)
        log.forward = value
        log.state_at_forward = (tmp_path / 'state.json').exists()

    def apply_nft(payload: bytes) -> None:
        log.nft.append(payload)
        if payload == delete_table_payload():
            if delete_error:
                raise NftablesError('delete failed')
            if not deletion_sticks:
                log.table = None
            return
        try:
            document = json.loads(payload.decode('utf-8'))
        except json.JSONDecodeError:
            return
        items = document.get('nftables')
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            create = item.get('create')
            if not isinstance(create, dict):
                continue
            table = create.get('table')
            if isinstance(table, dict):
                comment = table.get('comment')
                if isinstance(comment, str):
                    log.table = {'nftables': [{'table': {'comment': comment}}]}
                    return

    def list_nft() -> dict[str, object] | None:
        return log.table

    def nft_owner(listing: dict[str, object]) -> str | None:
        items = listing.get('nftables')
        if not isinstance(items, list):
            return None
        for item in items:
            if isinstance(item, dict):
                table = item.get('table')
                if isinstance(table, dict):
                    comment = table.get('comment')
                    if isinstance(comment, str) and comment.startswith('sslstrip-owner='):
                        return comment.split('=', 1)[1]
        return None

    def spawn(config: AppConfig, identities: tuple[int, int]) -> WorkerProcess:
        del config
        log.spawned = identities
        log.state_at_spawn = (tmp_path / 'state.json').exists()
        return proc

    def wait(proc_arg: WorkerProcess) -> int:
        del proc_arg
        return wait_code

    def send(proc_arg: WorkerProcess, signum: int) -> None:
        del proc_arg
        log.signals.append(signum)

    def signal_pid(pid: int, signum: int) -> None:
        assert signum == signal.SIGTERM
        log.terminated_pids.append(pid)
        process_starts.pop(pid, None)

    hooks = SupervisorHooks(
        geteuid=lambda: euid,
        sudo_ids=lambda: sudo,
        read_forward=read_forward,
        write_forward=write_forward,
        apply_nft=apply_nft,
        list_nft=list_nft,
        nft_owner=nft_owner,
        interface_address=lambda _name: '10.66.0.1',
        spawn_worker=spawn,
        wait_worker=wait,
        send_signal=send,
        process_start_time=process_starts.get,
        signal_pid=signal_pid,
    )
    return hooks, log


def test_managed_requires_root(tmp_path: Path) -> None:
    config = sample_config(manage_network=True, interface='dummy0', target=IPv4Address('10.66.0.2'), state_dir=tmp_path)
    hooks, _log = _hooks(tmp_path, euid=1000)
    with pytest.raises(ConfigError, match='root'):
        run_managed(config, hooks)


def test_direct_root_requires_run_as(tmp_path: Path) -> None:
    config = sample_config(manage_network=True, interface='dummy0', target=IPv4Address('10.66.0.2'), state_dir=tmp_path)
    hooks, _log = _hooks(tmp_path, sudo=None)
    with pytest.raises(ConfigError, match='--run-as'):
        run_managed(config, hooks)


def test_conflicting_nftables_refused(tmp_path: Path) -> None:
    config = sample_config(manage_network=True, interface='dummy0', target=IPv4Address('10.66.0.2'), state_dir=tmp_path)
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=other'}}]}
    hooks, _log = _hooks(tmp_path, existing_table=existing)
    with pytest.raises(ConfigError, match='already exists'):
        run_managed(config, hooks)


def test_conflicting_nftables_preserves_existing_state(tmp_path: Path) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    state = ManagedState('previous', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0)
    write_state(tmp_path, state)
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=previous'}}]}
    hooks, _log = _hooks(tmp_path, existing_table=existing)
    with pytest.raises(ConfigError, match='stale managed state'):
        run_managed(config, hooks)
    assert read_state(tmp_path).owner == 'previous'


def test_cleanup_refuses_foreign_owner(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=1,
            started_at=0.0,
        ),
    )
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=foreign'}}]}
    hooks, _log = _hooks(tmp_path, existing_table=existing)
    with pytest.raises(ConfigError, match='foreign'):
        cleanup_managed(config, hooks)


def test_cleanup_deletes_owned_table(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=1,
            started_at=0.0,
        ),
    )
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=ours'}}]}
    hooks, log = _hooks(tmp_path, existing_table=existing)
    assert cleanup_managed(config, hooks) == 0
    assert log.table is None
    assert '0' in log.writes
    assert not (tmp_path / 'state.json').exists()


def test_lock_exclusivity(tmp_path: Path) -> None:
    first = acquire_lock(tmp_path)
    with pytest.raises(ConfigError, match='already running'):
        acquire_lock(tmp_path)
    first.close()


def test_cleanup_refuses_while_session_holds_lock(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=1,
            started_at=0.0,
        ),
    )
    lock = acquire_lock(tmp_path)
    try:
        hooks, _log = _hooks(tmp_path)
        with pytest.raises(ConfigError, match='already running'):
            cleanup_managed(config, hooks)
    finally:
        lock.close()


def test_spawn_worker_drops_supplementary_groups(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _DummyPopen:
        def __init__(self, command: list[str], **kwargs: object) -> None:
            del command
            captured.update(kwargs)
            self.pid = 4321

    monkeypatch.setattr('sslstrip.supervisor.subprocess.Popen', _DummyPopen)
    spawn_worker_process(sample_config(), (1000, 1000))
    assert captured.get('user') == 1000
    assert captured.get('group') == 1000
    assert captured.get('extra_groups') == ()


def test_run_managed_installs_and_restores(tmp_path: Path) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
        listen_port=10000,
    )
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        hooks, log = _hooks(tmp_path)
        assert run_managed(config, hooks) == 0
        assert log.spawned == (1000, 1000)
        assert log.writes[0] == '1'
        assert log.state_at_forward
        assert log.writes[-1] == '0'
        assert len(log.nft) >= 2
        assert log.state_at_spawn
        handler = signal.getsignal(signal.SIGTERM)
        typed = cast('Callable[[int, FrameType | None], None]', handler)
        typed(signal.SIGTERM, None)
        assert log.signals == [signal.SIGTERM]
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def test_run_managed_preserves_state_when_table_deletion_fails(tmp_path: Path) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    hooks, log = _hooks(tmp_path, delete_error=True)
    assert run_managed(config, hooks) == 0
    assert log.table is not None
    assert (tmp_path / 'state.json').exists()


def test_run_managed_preserves_state_when_forwarding_restore_fails(tmp_path: Path) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    hooks, log = _hooks(tmp_path)
    write_forward = hooks.write_forward

    def fail_restore(value: str) -> None:
        if value == '0' and log.forward == '1':
            raise OSError('restore failed')
        write_forward(value)

    hooks.write_forward = fail_restore
    assert run_managed(config, hooks) == 0
    assert log.table is None
    assert (tmp_path / 'state.json').exists()


def test_run_managed_refuses_stale_state_without_side_effects(tmp_path: Path) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    write_state(
        tmp_path,
        ManagedState('previous', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0),
    )
    original = (tmp_path / 'state.json').read_bytes()
    hooks, log = _hooks(tmp_path)
    with pytest.raises(ConfigError, match='run sslstrip cleanup'):
        run_managed(config, hooks)
    assert (tmp_path / 'state.json').read_bytes() == original
    assert log.writes == []
    assert log.nft == []
    assert log.spawned is None


def test_state_write_failure_precedes_network_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    hooks, log = _hooks(tmp_path)

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise ConfigError('state write failed')

    monkeypatch.setattr('sslstrip.supervisor.write_state', fail_write)
    with pytest.raises(ConfigError, match='state write failed'):
        run_managed(config, hooks)
    assert log.writes == []
    assert log.nft == []
    assert log.spawned is None


def test_worker_is_stopped_when_pid_state_write_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    hooks, log = _hooks(tmp_path)
    real_write_state = write_state
    writes = 0

    def fail_second_write(
        state_dir: Path | StateDirectory,
        state: ManagedState,
        *,
        overwrite: bool = True,
    ) -> None:
        nonlocal writes
        writes += 1
        if writes == 2:
            raise ConfigError('pid state write failed')
        real_write_state(state_dir, state, overwrite=overwrite)

    monkeypatch.setattr('sslstrip.supervisor.write_state', fail_second_write)
    with pytest.raises(ConfigError, match='pid state write failed'):
        run_managed(config, hooks)
    assert log.signals == [signal.SIGTERM]
    assert log.table is None
    assert log.forward == '0'
    assert not (tmp_path / 'state.json').exists()


@pytest.mark.parametrize('missing', ['pid', 'identity'])
def test_run_managed_rejects_unidentifiable_worker(tmp_path: Path, missing: str) -> None:
    config = sample_config(
        manage_network=True,
        interface='dummy0',
        target=IPv4Address('10.66.0.2'),
        state_dir=tmp_path,
    )
    hooks, log = _hooks(tmp_path)
    if missing == 'pid':
        proc = _FakeProc()
        proc.pid = None
        hooks.spawn_worker = lambda _config, _ids: proc
    else:
        hooks.process_start_time = lambda _pid: None
    with pytest.raises(ConfigError, match=r'pid|identify'):
        run_managed(config, hooks)
    assert log.table is None
    assert log.forward == '0'
    assert not (tmp_path / 'state.json').exists()


def test_worker_command_contains_listen_settings() -> None:
    config = sample_config(listen_host='10.66.0.1', listen_port=9999, kill_sessions=True)
    command = worker_command(config)
    assert '--listen-host' in command
    assert '10.66.0.1' in command
    assert '--kill-sessions' in command
    assert '--worker' in command


def test_worker_command_optional_flags(tmp_path: Path) -> None:
    ca = tmp_path / 'ca.pem'
    ca.write_text('dummy', encoding='utf-8')
    log_path = tmp_path / 'traffic.log'
    config = sample_config(ca_file=ca, traffic_log_mode='all', traffic_log_file=log_path, verbose=2)
    command = worker_command(config)
    assert '--ca-file' in command
    assert '--traffic-log' in command
    assert 'all' in command
    assert command.count('-v') == 2


def test_cleanup_missing_state(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    hooks, _log = _hooks(tmp_path)
    with pytest.raises(ConfigError, match='no managed state'):
        cleanup_managed(config, hooks)


def test_cleanup_table_already_absent(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=1,
            started_at=0.0,
        ),
    )
    hooks, log = _hooks(tmp_path, existing_table=None)
    assert cleanup_managed(config, hooks) == 0
    assert '0' in log.writes
    assert not (tmp_path / 'state.json').exists()


def test_cleanup_stops_the_recorded_worker(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=4242,
            started_at=0.0,
            worker_start_time=12345,
        ),
    )
    hooks, log = _hooks(tmp_path)
    assert cleanup_managed(config, hooks) == 0
    assert log.terminated_pids == [4242]
    assert not (tmp_path / 'state.json').exists()


def test_cleanup_does_not_signal_a_reused_worker_pid(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=4242,
            started_at=0.0,
            worker_start_time=99999,
        ),
    )
    hooks, log = _hooks(tmp_path)
    assert cleanup_managed(config, hooks) == 0
    assert log.terminated_pids == []


def test_cleanup_preserves_state_when_forwarding_restore_fails(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState('ours', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0),
    )
    hooks, _log = _hooks(tmp_path)
    hooks.write_forward = lambda _value: (_ for _ in ()).throw(OSError('restore failed'))
    with pytest.raises(ConfigError, match='state retained'):
        cleanup_managed(config, hooks)
    assert (tmp_path / 'state.json').exists()


def test_cleanup_preserves_state_until_table_absence_is_confirmed(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState('ours', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0),
    )
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=ours'}}]}
    hooks, log = _hooks(tmp_path, existing_table=existing, deletion_sticks=True)
    with pytest.raises(NftablesError, match='still exists'):
        cleanup_managed(config, hooks)
    assert log.table is not None
    assert (tmp_path / 'state.json').exists()


def test_cleanup_refuses_unmarked_table(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    write_state(
        tmp_path,
        ManagedState(
            owner='ours',
            table='sslstrip',
            interface='dummy0',
            target='10.66.0.2',
            listen_host='10.66.0.1',
            listen_port=10000,
            previous_ip_forward='0',
            worker_pid=1,
            started_at=0.0,
        ),
    )
    existing: dict[str, object] = {'nftables': [{'table': {'name': 'sslstrip'}}]}
    hooks, _log = _hooks(tmp_path, existing_table=existing)
    with pytest.raises(ConfigError, match='ownership marker'):
        cleanup_managed(config, hooks)


def test_managed_state_round_trip(tmp_path: Path) -> None:
    state = ManagedState(
        owner='abc',
        table='sslstrip',
        interface='dummy0',
        target='10.66.0.2',
        listen_host='10.66.0.1',
        listen_port=10000,
        previous_ip_forward='0',
        worker_pid=9,
        started_at=1.5,
        worker_start_time=123,
    )
    write_state(tmp_path, state)
    loaded = read_state(tmp_path)
    assert loaded.owner == 'abc'
    assert loaded.worker_pid == 9
    assert loaded.worker_start_time == 123


def test_managed_state_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / 'state.json'
    path.write_text('[]', encoding='utf-8')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match='JSON object'):
        read_state(tmp_path)
    path.write_text('{', encoding='utf-8')
    path.chmod(0o600)
    with pytest.raises(ConfigError, match='cannot read'):
        read_state(tmp_path)


def test_managed_state_from_json_missing_fields() -> None:
    with pytest.raises(ConfigError, match='required'):
        ManagedState.from_json({'owner': 'x'})


def test_default_hooks_sudo_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv('SUDO_UID', '1000')
    monkeypatch.setenv('SUDO_GID', '1000')
    hooks = default_hooks(sample_config())
    assert hooks.sudo_ids() == (1000, 1000)
    assert hooks.geteuid() == os.geteuid()
    monkeypatch.setenv('SUDO_UID', 'nope')
    assert hooks.sudo_ids() is None
    monkeypatch.delenv('SUDO_UID')
    assert hooks.sudo_ids() is None


def test_resolve_run_as_numeric() -> None:
    uid, gid = parse_run_as('0')
    assert uid == 0
    assert isinstance(gid, int)


def test_cleanup_requires_root(tmp_path: Path) -> None:
    config = sample_config(state_dir=tmp_path)
    hooks, _log = _hooks(tmp_path, euid=1000)
    with pytest.raises(ConfigError, match='root'):
        cleanup_managed(config, hooks)


def test_safe_delete_rejects_inspection_and_ownership_failures(tmp_path: Path) -> None:
    hooks, _log = _hooks(tmp_path)

    def query_error() -> dict[str, object] | None:
        raise NftablesError('query failed')

    hooks.list_nft = query_error
    assert not _safe_delete_table(hooks, 'ours')

    listing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=ours'}}]}
    hooks.list_nft = lambda: listing
    hooks.nft_owner = lambda _listing: (_ for _ in ()).throw(NftablesError('ambiguous'))
    assert not _safe_delete_table(hooks, 'ours')


def test_safe_delete_rejects_foreign_table(tmp_path: Path) -> None:
    existing: dict[str, object] = {'nftables': [{'table': {'comment': 'sslstrip-owner=foreign'}}]}
    hooks, _log = _hooks(tmp_path, existing_table=existing)
    assert not _safe_delete_table(hooks, 'ours')


def test_state_directory_rejects_symlink_and_unsafe_mode(tmp_path: Path) -> None:
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    link = tmp_path / 'link'
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ConfigError, match='managed state directory'):
        prepare_state_dir(link)

    unsafe = tmp_path / 'unsafe'
    unsafe.mkdir()
    unsafe.chmod(0o755)
    with pytest.raises(ConfigError, match='mode 0700'):
        prepare_state_dir(unsafe)
    assert unsafe.stat().st_mode & 0o777 == 0o755


def test_state_directory_rejects_wrong_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    actual_uid = os.geteuid()
    monkeypatch.setattr('sslstrip.supervisor.os.geteuid', lambda: actual_uid + 1)
    with pytest.raises(ConfigError, match='owner'):
        prepare_state_dir(tmp_path)


def test_state_directory_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / 'real'
    real.mkdir(mode=0o700)
    link = tmp_path / 'parent-link'
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ConfigError, match='managed state directory'):
        prepare_state_dir(link / 'state')
    assert not (real / 'state').exists()


def test_state_temp_symlink_cannot_clobber_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Token:
        hex = 'fixed'

    victim = tmp_path / 'victim'
    victim.write_text('unchanged', encoding='utf-8')
    (tmp_path / '.state.json.fixed.tmp').symlink_to(victim)
    monkeypatch.setattr('sslstrip.supervisor.uuid.uuid4', lambda: Token())
    state = ManagedState('ours', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0)
    with pytest.raises(ConfigError, match='cannot safely create'):
        write_state(tmp_path, state)
    assert victim.read_text(encoding='utf-8') == 'unchanged'


def test_lock_and_state_symlinks_are_rejected(tmp_path: Path) -> None:
    victim = tmp_path / 'victim'
    victim.write_text('unchanged', encoding='utf-8')
    (tmp_path / 'lock').symlink_to(victim)
    with pytest.raises(ConfigError, match='safely open managed lock'):
        acquire_lock(tmp_path)
    assert victim.read_text(encoding='utf-8') == 'unchanged'

    (tmp_path / 'lock').unlink()
    (tmp_path / 'state.json').symlink_to(victim)
    with pytest.raises(ConfigError, match='cannot read managed state'):
        read_state(tmp_path)
    assert victim.read_text(encoding='utf-8') == 'unchanged'


def test_state_directory_creation_and_parent_validation(tmp_path: Path) -> None:
    nested = tmp_path / 'one' / 'two'
    directory = prepare_state_dir(nested)
    directory.close()
    assert nested.is_dir()
    assert nested.stat().st_mode & 0o777 == 0o700
    assert nested.parent.stat().st_mode & 0o777 == 0o700

    unsafe_parent = tmp_path / 'unsafe-parent'
    unsafe_parent.mkdir(mode=0o700)
    unsafe_parent.chmod(0o777)
    with pytest.raises(ConfigError, match='unsafe permissions'):
        prepare_state_dir(unsafe_parent / 'state')
    assert not (unsafe_parent / 'state').exists()

    with pytest.raises(ConfigError, match='unsafe managed state directory'):
        prepare_state_dir(tmp_path / 'missing', create=False)


def test_state_entries_require_safe_modes_and_no_clobber(tmp_path: Path) -> None:
    state = ManagedState('ours', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', 1, 0.0)
    write_state(tmp_path, state)
    with pytest.raises(ConfigError, match='stale managed state'):
        write_state(tmp_path, state, overwrite=False)

    (tmp_path / 'state.json').chmod(0o644)
    with pytest.raises(ConfigError, match='unsafe managed state entry'):
        read_state(tmp_path)
    (tmp_path / 'state.json').unlink()
    remove_state(tmp_path)


def test_process_start_time_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _process_start_time(os.getpid()) is not None

    monkeypatch.setattr(Path, 'read_text', lambda *_args, **_kwargs: 'malformed')
    assert _process_start_time(1) is None
    monkeypatch.setattr(Path, 'read_text', lambda *_args, **_kwargs: '1 (name) S')
    assert _process_start_time(1) is None

    def fail_read(*_args: object, **_kwargs: object) -> str:
        raise OSError('gone')

    monkeypatch.setattr(Path, 'read_text', fail_read)
    assert _process_start_time(1) is None


def test_recorded_worker_stop_failures_retain_state(monkeypatch: pytest.MonkeyPatch) -> None:
    state = ManagedState(
        'ours',
        'sslstrip',
        'dummy0',
        '10.66.0.2',
        '10.66.0.1',
        10000,
        '0',
        4242,
        0.0,
        worker_start_time=12345,
    )
    hooks, _log = _hooks(Path('.'))
    hooks.signal_pid = lambda _pid, _signum: (_ for _ in ()).throw(ProcessLookupError())
    _stop_recorded_worker(state, hooks)

    hooks.signal_pid = lambda _pid, _signum: (_ for _ in ()).throw(OSError('denied'))
    with pytest.raises(ConfigError, match='state retained'):
        _stop_recorded_worker(state, hooks)

    hooks.signal_pid = lambda _pid, _signum: None
    hooks.process_start_time = lambda _pid: 12345
    monkeypatch.setattr('sslstrip.supervisor.time.sleep', lambda _seconds: None)
    with pytest.raises(ConfigError, match='did not stop'):
        _stop_recorded_worker(state, hooks)


def test_worker_stop_helpers_handle_absent_processes(tmp_path: Path) -> None:
    hooks, _log = _hooks(tmp_path)
    proc = _FakeProc()
    hooks.send_signal = lambda _proc, _signum: (_ for _ in ()).throw(ProcessLookupError())
    assert _safe_stop_spawned_worker(proc, hooks)

    hooks.send_signal = lambda _proc, _signum: (_ for _ in ()).throw(OSError('denied'))
    assert not _safe_stop_spawned_worker(proc, hooks)

    no_pid = ManagedState('ours', 'sslstrip', 'dummy0', '10.66.0.2', '10.66.0.1', 10000, '0', None, 0.0)
    _stop_recorded_worker(no_pid, hooks)
    gone = ManagedState(
        'ours',
        'sslstrip',
        'dummy0',
        '10.66.0.2',
        '10.66.0.1',
        10000,
        '0',
        99,
        0.0,
        worker_start_time=1,
    )
    hooks.process_start_time = lambda _pid: None
    _stop_recorded_worker(gone, hooks)

    hooks.list_nft = lambda: None
    assert _safe_delete_table(hooks, 'ours')


def test_state_directory_rejects_wrong_final_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    actual_uid = os.geteuid()
    monkeypatch.setattr('sslstrip.supervisor.os.geteuid', lambda: actual_uid + 1)
    with pytest.raises(ConfigError, match='owned by uid'):
        prepare_state_dir(Path('/tmp'), create=False)
