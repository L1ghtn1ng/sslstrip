"""Root supervisor: lock, nftables, forwarding, privilege drop, cleanup."""

import fcntl
import json
import logging
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path
from types import FrameType
from typing import IO, Protocol, TextIO, cast

from sslstrip.config import TRUSTED_STICKY_DIRS, AppConfig, ConfigError, interface_ipv4
from sslstrip.nftables import (
    NftablesError,
    RedirectSpec,
    apply_json,
    create_table_payload,
    delete_table_payload,
    list_table,
    table_owner,
)

logger = logging.getLogger('sslstrip')

FORWARD_PATH = Path('/proc/sys/net/ipv4/ip_forward')
STATE_NAME = 'state.json'
LOCK_NAME = 'lock'


@dataclass
class StateDirectory:
    """Pinned descriptor for the validated managed-state directory."""

    path: Path
    fd: int

    def close(self) -> None:
        os.close(self.fd)


@dataclass
class ManagedState:
    """Persisted description of an active or crashed managed session."""

    owner: str
    table: str
    interface: str
    target: str
    listen_host: str
    listen_port: int
    previous_ip_forward: str
    worker_pid: int | None
    started_at: float
    worker_start_time: int | None = None

    def to_json(self) -> dict[str, object]:
        return {
            'version': 1,
            'owner': self.owner,
            'table': self.table,
            'interface': self.interface,
            'target': self.target,
            'listen_host': self.listen_host,
            'listen_port': self.listen_port,
            'previous_ip_forward': self.previous_ip_forward,
            'worker_pid': self.worker_pid,
            'worker_start_time': self.worker_start_time,
            'started_at': self.started_at,
        }

    @classmethod
    def from_json(cls, data: dict[str, object]) -> ManagedState:
        owner = data.get('owner')
        interface = data.get('interface')
        target = data.get('target')
        listen_host = data.get('listen_host')
        listen_port = data.get('listen_port')
        previous = data.get('previous_ip_forward')
        if not isinstance(owner, str) or not isinstance(interface, str) or not isinstance(target, str):
            raise ConfigError('managed state file is missing required string fields')
        if not isinstance(listen_host, str) or not isinstance(listen_port, int) or not isinstance(previous, str):
            raise ConfigError('managed state file is missing required fields')
        worker_pid = data.get('worker_pid')
        worker_start_time = data.get('worker_start_time')
        started_at = data.get('started_at')
        pid = worker_pid if isinstance(worker_pid, int) else None
        process_start = worker_start_time if isinstance(worker_start_time, int) else None
        started = float(started_at) if isinstance(started_at, (int, float)) else time.time()
        table = data.get('table')
        table_name = table if isinstance(table, str) else 'sslstrip'
        return cls(
            owner=owner,
            table=table_name,
            interface=interface,
            target=target,
            listen_host=listen_host,
            listen_port=listen_port,
            previous_ip_forward=previous,
            worker_pid=pid,
            started_at=started,
            worker_start_time=process_start,
        )


class WorkerProcess(Protocol):
    """Subset of ``subprocess.Popen`` used by the supervisor."""

    @property
    def pid(self) -> int | None: ...

    def send_signal(self, signum: int, /) -> None: ...

    def wait(self) -> int: ...


@dataclass
class SupervisorHooks:
    """Injectable OS operations so supervisor logic can be unit-tested."""

    geteuid: Callable[[], int]
    sudo_ids: Callable[[], tuple[int, int] | None]
    read_forward: Callable[[], str]
    write_forward: Callable[[str], None]
    apply_nft: Callable[[bytes], None]
    list_nft: Callable[[], dict[str, object] | None]
    nft_owner: Callable[[dict[str, object]], str | None]
    interface_address: Callable[[str], str]
    spawn_worker: Callable[[AppConfig, tuple[int, int]], WorkerProcess]
    wait_worker: Callable[[WorkerProcess], int]
    send_signal: Callable[[WorkerProcess, int], None]
    process_start_time: Callable[[int], int | None]
    signal_pid: Callable[[int, int], None]


def default_hooks(config: AppConfig) -> SupervisorHooks:
    """Build hooks that talk to the real OS and ``nft`` executable."""

    def _sudo_ids() -> tuple[int, int] | None:
        uid = os.environ.get('SUDO_UID')
        gid = os.environ.get('SUDO_GID')
        if uid is None or gid is None:
            return None
        try:
            return int(uid), int(gid)
        except ValueError:
            return None

    def _read_forward() -> str:
        return FORWARD_PATH.read_text(encoding='ascii').strip()

    def _write_forward(value: str) -> None:
        FORWARD_PATH.write_text(value + '\n', encoding='ascii')

    def _apply(payload: bytes) -> None:
        apply_json(config.nft_executable, payload)

    def _list() -> dict[str, object] | None:
        return list_table(config.nft_executable)

    def _spawn(worker_config: AppConfig, identities: tuple[int, int]) -> WorkerProcess:
        return spawn_worker_process(worker_config, identities)

    def _wait(proc: WorkerProcess) -> int:
        return int(proc.wait())

    def _signal(proc: WorkerProcess, signum: int) -> None:
        proc.send_signal(signum)

    def _address(name: str) -> str:
        return str(interface_ipv4(name))

    return SupervisorHooks(
        geteuid=os.geteuid,
        sudo_ids=_sudo_ids,
        read_forward=_read_forward,
        write_forward=_write_forward,
        apply_nft=_apply,
        list_nft=_list,
        nft_owner=table_owner,
        interface_address=_address,
        spawn_worker=_spawn,
        wait_worker=_wait,
        send_signal=_signal,
        process_start_time=_process_start_time,
        signal_pid=os.kill,
    )


def run_managed(config: AppConfig, hooks: SupervisorHooks | None = None) -> int:
    """Acquire exclusive lock, install nftables, run the worker, then restore."""
    ops = hooks if hooks is not None else default_hooks(config)
    if ops.geteuid() != 0:
        raise ConfigError('managed mode requires root (use sudo)')
    worker_ids = _worker_identities(config, ops)
    if config.interface is None or config.target is None:
        raise ConfigError('--manage-network requires --interface and --target')
    listen_host = ops.interface_address(config.interface)
    worker_config = replace(config, listen_host=listen_host, manage_network=False, run_as=None, worker=True)
    directory = prepare_state_dir(config.state_dir)
    try:
        lock_fd = acquire_lock(directory)
        owner = str(uuid.uuid4())
        previous = ''
        forwarding_changed = False
        state_written = False
        proc: WorkerProcess | None = None
        worker_stopped = True
        try:
            if state_exists(directory):
                raise ConfigError(f'stale managed state exists at {config.state_dir / STATE_NAME}; run sslstrip cleanup')
            previous = ops.read_forward()
            state = ManagedState(
                owner=owner,
                table='sslstrip',
                interface=config.interface,
                target=str(config.target),
                listen_host=listen_host,
                listen_port=config.listen_port,
                previous_ip_forward=previous,
                worker_pid=None,
                started_at=time.time(),
            )
            existing = ops.list_nft()
            if existing is not None:
                existing_owner = ops.nft_owner(existing)
                raise ConfigError(
                    'nftables table ip sslstrip already exists' + (f' (owner {existing_owner})' if existing_owner else '')
                )
            spec = RedirectSpec(
                interface=config.interface,
                target=config.target,
                proxy_port=config.listen_port,
                owner=owner,
            )
            write_state(directory, state, overwrite=False)
            state_written = True
            if previous != '1':
                forwarding_changed = True
                ops.write_forward('1')
            ops.apply_nft(create_table_payload(spec))
            with _blocked_worker_signals():
                proc = ops.spawn_worker(worker_config, worker_ids)
                worker_stopped = False
                if proc.pid is None:
                    raise ConfigError('worker process did not report a pid')
                worker_start_time = ops.process_start_time(proc.pid)
                if worker_start_time is None:
                    raise ConfigError('could not identify worker process')
                _install_signal_forwarding(proc, ops)
                write_state(
                    directory,
                    replace(state, worker_pid=int(proc.pid), worker_start_time=worker_start_time),
                )
            result = ops.wait_worker(proc)
            worker_stopped = True
            return result
        finally:
            if proc is not None and not worker_stopped:
                worker_stopped = _safe_stop_spawned_worker(proc, ops)
            table_absent = _safe_delete_table(ops, owner) if state_written else False
            forwarding_restored = True
            if forwarding_changed:
                try:
                    ops.write_forward(previous)
                except OSError as exc:
                    logger.error('Failed to restore ip_forward=%s: %s', previous, exc)
                    forwarding_restored = False
            if state_written and worker_stopped and table_absent and forwarding_restored:
                remove_state(directory)
            lock_fd.close()
    finally:
        directory.close()


def cleanup_managed(config: AppConfig, hooks: SupervisorHooks | None = None) -> int:
    """Remove owned nftables state after an ungraceful stop."""
    ops = hooks if hooks is not None else default_hooks(config)
    if ops.geteuid() != 0:
        raise ConfigError('cleanup requires root (use sudo)')
    directory = prepare_state_dir(config.state_dir, create=False)
    try:
        if not state_exists(directory):
            raise ConfigError(f'no managed state file at {config.state_dir / STATE_NAME}')
        lock_fd = acquire_lock(directory)
        try:
            state = read_state(directory)
            listing = ops.list_nft()
            if listing is None:
                logger.warning('nftables table already absent; removing state file')
                _stop_recorded_worker(state, ops)
                try:
                    ops.write_forward(state.previous_ip_forward)
                except OSError as exc:
                    raise ConfigError('could not restore ip_forward; managed state retained') from exc
                remove_state(directory)
                return 0
            listed_owner = ops.nft_owner(listing)
            if listed_owner is None:
                raise ConfigError('refusing to delete nftables table without an sslstrip ownership marker')
            if listed_owner != state.owner:
                raise ConfigError(f'refusing to delete foreign nftables table (owner {listed_owner})')
            _stop_recorded_worker(state, ops)
            ops.apply_nft(delete_table_payload())
            if ops.list_nft() is not None:
                raise NftablesError('nftables table still exists after deletion')
            try:
                ops.write_forward(state.previous_ip_forward)
            except OSError as exc:
                raise ConfigError('could not restore ip_forward; managed state retained') from exc
            remove_state(directory)
            return 0
        finally:
            lock_fd.close()
    finally:
        directory.close()


def prepare_state_dir(state_dir: Path, *, create: bool = True) -> StateDirectory:
    """Open a non-symlink state directory owned by the effective user."""
    if create:
        try:
            fd = _open_directory_path(state_dir, create=True)
        except OSError as exc:
            raise ConfigError(f'cannot create managed state directory {state_dir}') from exc
    else:
        try:
            fd = _open_directory_path(state_dir, create=False)
        except OSError as exc:
            raise ConfigError(f'unsafe managed state directory {state_dir}') from exc
    try:
        details = os.fstat(fd)
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.geteuid():
            raise ConfigError(f'managed state directory must be owned by uid {os.geteuid()}: {state_dir}')
        if stat.S_IMODE(details.st_mode) != 0o700:
            raise ConfigError(f'managed state directory must have mode 0700: {state_dir}')
    except Exception:
        os.close(fd)
        raise
    return StateDirectory(state_dir, fd)


def _open_directory_path(path: Path, *, create: bool) -> int:
    absolute = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        components = absolute.parts[1:]
        for index, component in enumerate(components):
            child_created = False
            try:
                next_fd = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=fd)
                    child_created = True
                except FileExistsError:
                    pass
                next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            child_path = Path(*absolute.parts[: index + 2])
            if child_created:
                os.fchmod(fd, 0o700)
            if index < len(components) - 1:
                _validate_state_parent(fd, child_path)
    except Exception:
        os.close(fd)
        raise
    return fd


def _validate_state_parent(fd: int, path: Path) -> None:
    details = os.fstat(fd)
    mode = stat.S_IMODE(details.st_mode)
    trusted_owner = details.st_uid in {0, os.geteuid()}
    shared_system_directory = path in TRUSTED_STICKY_DIRS
    trusted_sticky_directory = bool(details.st_mode & stat.S_ISVTX) and (trusted_owner or shared_system_directory)
    if not trusted_owner and not trusted_sticky_directory:
        raise ConfigError(f'unsafe owner on managed state directory ancestor {path}')
    if mode & 0o022 and not trusted_sticky_directory:
        raise ConfigError(f'unsafe permissions on managed state directory ancestor {path}')


def acquire_lock(state_dir: Path | StateDirectory) -> IO[bytes]:
    """Open an exclusive non-blocking lock file in the state directory."""
    with _state_directory(state_dir) as directory:
        try:
            fd = os.open(
                LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory.fd,
            )
        except OSError as exc:
            raise ConfigError(f'cannot safely open managed lock file in {directory.path}') from exc
    try:
        _validate_state_file(fd, LOCK_NAME)
        os.fchmod(fd, 0o600)
        lock_fd = os.fdopen(fd, 'a+b')
    except Exception:
        os.close(fd)
        raise
    try:
        fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        lock_fd.close()
        raise ConfigError('another managed sslstrip session is already running') from exc
    return lock_fd


def write_state(state_dir: Path | StateDirectory, state: ManagedState, *, overwrite: bool = True) -> None:
    """Atomically write a 0600 JSON state file."""
    payload = json.dumps(state.to_json(), indent=2) + '\n'
    tmp_name = f'.{STATE_NAME}.{uuid.uuid4().hex}.tmp'
    with _state_directory(state_dir) as directory:
        try:
            fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory.fd,
            )
        except OSError as exc:
            raise ConfigError(f'cannot safely create managed state in {directory.path}') from exc
        try:
            os.fchmod(fd, 0o600)
            stream = os.fdopen(fd, 'w', encoding='utf-8')
            fd = -1
            with stream:
                _write_state_payload(stream, payload)
            if overwrite:
                os.replace(tmp_name, STATE_NAME, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
            else:
                try:
                    os.link(
                        tmp_name,
                        STATE_NAME,
                        src_dir_fd=directory.fd,
                        dst_dir_fd=directory.fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise ConfigError(
                        f'stale managed state exists at {directory.path / STATE_NAME}; run sslstrip cleanup'
                    ) from exc
                os.unlink(tmp_name, dir_fd=directory.fd)
            os.fsync(directory.fd)
        finally:
            if fd >= 0:
                os.close(fd)
            with suppress(FileNotFoundError):
                os.unlink(tmp_name, dir_fd=directory.fd)


def read_state(state_dir: Path | StateDirectory) -> ManagedState:
    """Load and validate the managed state file."""
    with _state_directory(state_dir) as directory:
        fd = -1
        try:
            fd = os.open(STATE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory.fd)
            _validate_state_file(fd, STATE_NAME)
            stream = os.fdopen(fd, encoding='utf-8')
            fd = -1
            with stream:
                loaded = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ConfigError(f'cannot read managed state file {directory.path / STATE_NAME}') from exc
        finally:
            if fd >= 0:
                os.close(fd)
    if not isinstance(loaded, dict):
        raise ConfigError('managed state file is not a JSON object')
    return ManagedState.from_json(loaded)


def remove_state(state_dir: Path | StateDirectory) -> None:
    """Remove the state file if it exists."""
    with _state_directory(state_dir) as directory:
        try:
            os.unlink(STATE_NAME, dir_fd=directory.fd)
            os.fsync(directory.fd)
        except FileNotFoundError:
            return


def state_exists(state_dir: Path | StateDirectory) -> bool:
    """Return whether any directory entry occupies the managed-state name."""
    with _state_directory(state_dir) as directory:
        try:
            os.stat(STATE_NAME, dir_fd=directory.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True


@contextmanager
def _state_directory(state_dir: Path | StateDirectory) -> Iterator[StateDirectory]:
    if isinstance(state_dir, StateDirectory):
        yield state_dir
        return
    directory = prepare_state_dir(state_dir, create=False)
    try:
        yield directory
    finally:
        directory.close()


def _validate_state_file(fd: int, name: str) -> None:
    details = os.fstat(fd)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
        raise ConfigError(f'unsafe managed state entry: {name}')


def _write_state_payload(stream: TextIO, payload: str) -> None:
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())


def spawn_worker_process(config: AppConfig, identities: tuple[int, int]) -> WorkerProcess:
    """Start the Twisted worker as ``identities`` (uid, gid)."""
    command = worker_command(config)
    uid, gid = identities
    proc = subprocess.Popen(
        command,
        user=uid,
        group=gid,
        extra_groups=(),
        stdin=subprocess.DEVNULL,
        shell=False,
    )
    return cast('WorkerProcess', proc)


def worker_command(config: AppConfig) -> list[str]:
    """Argument vector used to spawn the unprivileged worker."""
    command = [
        sys.executable,
        '-m',
        'sslstrip',
        'run',
        '--worker',
        '--listen-host',
        config.listen_host,
        '--listen-port',
        str(config.listen_port),
        '--max-body-size',
        str(config.max_body_size),
        '--connect-timeout',
        str(config.connect_timeout),
        '--response-timeout',
        str(config.response_timeout),
        '--nft-executable',
        config.nft_executable,
        '--state-dir',
        str(config.state_dir),
    ]
    if config.kill_sessions:
        command.append('--kill-sessions')
    if config.ca_file is not None:
        command.extend(['--ca-file', str(config.ca_file)])
    if config.traffic_log_mode != 'off' and config.traffic_log_file is not None:
        command.extend(['--traffic-log', config.traffic_log_mode, '--traffic-log-file', str(config.traffic_log_file)])
    if config.verbose:
        command.extend(['-v'] * config.verbose)
    return command


def _worker_identities(config: AppConfig, hooks: SupervisorHooks) -> tuple[int, int]:
    if config.run_as is not None:
        return config.run_as
    sudo = hooks.sudo_ids()
    if sudo is not None:
        return sudo
    raise ConfigError('direct root invocation requires --run-as USER[:GROUP]')


def _install_signal_forwarding(proc: WorkerProcess, hooks: SupervisorHooks) -> None:
    def _forward(signum: int, frame: FrameType | None) -> None:
        del frame
        try:
            hooks.send_signal(proc, signum)
        except OSError:
            logger.debug('Failed to forward signal %s', signum, exc_info=True)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)
    signal.signal(signal.SIGHUP, _forward)


@contextmanager
def _blocked_worker_signals() -> Iterator[None]:
    forwarded = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, forwarded)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _process_start_time(pid: int) -> int | None:
    try:
        stat_line = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    except FileNotFoundError, PermissionError, OSError, UnicodeError:
        return None
    closing_parenthesis = stat_line.rfind(')')
    if closing_parenthesis < 0:
        return None
    fields = stat_line[closing_parenthesis + 1 :].split()
    try:
        return int(fields[19])
    except IndexError, ValueError:
        return None


def _safe_stop_spawned_worker(proc: WorkerProcess, hooks: SupervisorHooks) -> bool:
    try:
        hooks.send_signal(proc, signal.SIGTERM)
        hooks.wait_worker(proc)
    except ProcessLookupError:
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        logger.error('Failed to stop managed worker: %s', exc)
        return False
    return True


def _stop_recorded_worker(state: ManagedState, hooks: SupervisorHooks) -> None:
    pid = state.worker_pid
    expected_start = state.worker_start_time
    if pid is None:
        return
    if expected_start is None:
        logger.warning('Managed state lacks worker identity; not signalling pid %s', pid)
        return
    current_start = hooks.process_start_time(pid)
    if current_start is None:
        return
    if current_start != expected_start:
        logger.warning('Managed worker pid %s has been reused; not signalling it', pid)
        return
    try:
        hooks.signal_pid(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise ConfigError('could not stop managed worker; managed state retained') from exc
    for _ in range(100):
        if hooks.process_start_time(pid) != expected_start:
            return
        time.sleep(0.05)
    raise ConfigError('managed worker did not stop; managed state retained')


def _safe_delete_table(hooks: SupervisorHooks, owner: str) -> bool:
    try:
        listing = hooks.list_nft()
    except NftablesError as exc:
        logger.error('Failed to inspect nftables table: %s', exc)
        return False
    if listing is None:
        return True
    try:
        listed_owner = hooks.nft_owner(listing)
    except NftablesError as exc:
        logger.error('Failed to verify nftables table ownership: %s', exc)
        return False
    if listed_owner != owner:
        logger.error('Refusing to delete nftables table owned by %s', listed_owner)
        return False
    try:
        hooks.apply_nft(delete_table_payload())
        if hooks.list_nft() is None:
            return True
        logger.error('nftables table still exists after deletion')
        return False
    except NftablesError as exc:
        logger.error('Failed to delete nftables table: %s', exc)
        return False
