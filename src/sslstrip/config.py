"""Application configuration parsed from the sslstrip CLI."""

import argparse
import grp
import os
import pwd
import socket
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from typing import Literal

from sslstrip import __version__
from sslstrip.logs import TrafficMode

DEFAULT_LISTEN_PORT = 10000
DEFAULT_LISTEN_HOST = '127.0.0.1'
DEFAULT_MAX_BODY_SIZE = 8 * 1024 * 1024
DEFAULT_CONNECT_TIMEOUT = 10.0
DEFAULT_RESPONSE_TIMEOUT = 30.0
DEFAULT_STATE_DIR = Path('/run/sslstrip')
DEFAULT_LINK_TTL_SECONDS = 30 * 60
DEFAULT_LINK_LIMIT = 10_000
INTERFACE_NAME_RE_MAX = 16
TRUSTED_STICKY_DIRS = frozenset({Path('/') / 'tmp', Path('/var') / 'tmp', Path('/dev') / 'shm'})


class ConfigError(ValueError):
    """CLI or environment configuration is invalid."""


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable runtime configuration for one sslstrip process."""

    command: Literal['run', 'doctor', 'cleanup']
    listen_host: str
    listen_port: int
    manage_network: bool
    interface: str | None
    target: IPv4Address | None
    run_as: tuple[int, int] | None
    kill_sessions: bool
    max_body_size: int
    connect_timeout: float
    response_timeout: float
    ca_file: Path | None
    traffic_log_mode: TrafficMode
    traffic_log_file: Path | None
    state_dir: Path
    link_ttl_seconds: float
    link_limit: int
    nft_executable: str
    verbose: int
    worker: bool


def build_parser() -> argparse.ArgumentParser:
    """Build the public argparse parser."""
    parser = argparse.ArgumentParser(
        prog='sslstrip',
        description='sslstrip 5.0 — HTTPS stripping proxy for authorized Linux lab use',
    )
    parser.add_argument('--version', '-V', action='version', version=version_string())
    sub = parser.add_subparsers(dest='command')

    run = sub.add_parser('run', help='start the stripping proxy')
    run.add_argument('--listen-port', '-l', type=int, default=DEFAULT_LISTEN_PORT, help='port to listen on')
    run.add_argument(
        '--listen-host', default=None, help='address to bind (default: 127.0.0.1, or the interface address in managed mode)'
    )
    run.add_argument('--manage-network', action='store_true', help='enable IPv4 forwarding and a target-scoped nftables redirect')
    run.add_argument('--interface', default=None, help='interface for managed mode')
    run.add_argument('--target', default=None, help='single target IPv4 address for managed mode')
    run.add_argument('--run-as', default=None, help='user or uid[:gid] for the Twisted worker when running as root')
    run.add_argument('--kill-sessions', '-k', action='store_true', help='expire cookies on the first request from each client')
    run.add_argument('--max-body-size', type=int, default=DEFAULT_MAX_BODY_SIZE, help='decoded-body rewrite limit in bytes')
    run.add_argument('--connect-timeout', type=float, default=DEFAULT_CONNECT_TIMEOUT, help='upstream connect timeout in seconds')
    run.add_argument(
        '--response-timeout', type=float, default=DEFAULT_RESPONSE_TIMEOUT, help='upstream response timeout in seconds'
    )
    run.add_argument('--ca-file', default=None, help='PEM file with extra lab certificate authorities')
    run.add_argument(
        '--traffic-log',
        choices=('post', 'secure', 'all'),
        default=None,
        help='unredacted traffic log mode (requires --traffic-log-file)',
    )
    run.add_argument('--traffic-log-file', default=None, help='path for unredacted traffic log')
    run.add_argument('--state-dir', default=str(DEFAULT_STATE_DIR), help='directory for managed-mode lock and state')
    run.add_argument('-v', '--verbose', action='count', default=0, help='increase operational log verbosity')
    run.add_argument('--nft-executable', default=os.environ.get('SSLSTRIP_NFT', 'nft'), help=argparse.SUPPRESS)
    run.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)

    doctor = sub.add_parser('doctor', help='run read-only environment checks')
    doctor.add_argument('--interface', default=None)
    doctor.add_argument('--target', default=None)
    doctor.add_argument('--listen-port', '-l', type=int, default=DEFAULT_LISTEN_PORT)
    doctor.add_argument('--listen-host', default=DEFAULT_LISTEN_HOST)
    doctor.add_argument('--ca-file', default=None)
    doctor.add_argument('--state-dir', default=str(DEFAULT_STATE_DIR))
    doctor.add_argument('--nft-executable', default=os.environ.get('SSLSTRIP_NFT', 'nft'), help=argparse.SUPPRESS)
    doctor.add_argument('-v', '--verbose', action='count', default=0)

    cleanup = sub.add_parser('cleanup', help='recover a stale managed session')
    cleanup.add_argument('--state-dir', default=str(DEFAULT_STATE_DIR), help='directory containing managed-mode state')
    cleanup.add_argument('--nft-executable', default=os.environ.get('SSLSTRIP_NFT', 'nft'), help=argparse.SUPPRESS)
    cleanup.add_argument('-v', '--verbose', action='count', default=0)
    return parser


def parse_config(arguments: list[str] | None = None) -> AppConfig:
    """Parse command-line arguments into an application configuration."""
    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.command is None:
        parser.error('a command is required (run, doctor, cleanup)')
    return config_from_namespace(args)


def config_from_namespace(args: argparse.Namespace) -> AppConfig:
    """Validate a parsed argparse namespace into AppConfig."""
    command: Literal['run', 'doctor', 'cleanup'] = args.command
    manage_network = bool(getattr(args, 'manage_network', False))
    interface = getattr(args, 'interface', None)
    target_raw = getattr(args, 'target', None)
    target: IPv4Address | None = None
    if target_raw is not None:
        try:
            target = IPv4Address(target_raw)
        except AddressValueError as exc:
            raise ConfigError(f'invalid target IPv4 address: {target_raw}') from exc
    if manage_network and command == 'run':
        if interface is None or interface == '':
            raise ConfigError('--manage-network requires --interface')
        if target is None:
            raise ConfigError('--manage-network requires --target')
        validate_interface_name(interface)
    listen_port = int(getattr(args, 'listen_port', DEFAULT_LISTEN_PORT))
    if listen_port < 1 or listen_port > 65535:
        raise ConfigError('listen port must be between 1 and 65535')
    listen_host = getattr(args, 'listen_host', None)
    if listen_host is None:
        listen_host = DEFAULT_LISTEN_HOST
    traffic_mode_raw = getattr(args, 'traffic_log', None)
    traffic_file_raw = getattr(args, 'traffic_log_file', None)
    if command == 'run':
        if traffic_mode_raw is not None and traffic_file_raw is None:
            raise ConfigError('--traffic-log requires --traffic-log-file')
        if traffic_file_raw is not None and traffic_mode_raw is None:
            raise ConfigError('--traffic-log-file requires --traffic-log')
    traffic_mode: TrafficMode = traffic_mode_raw if traffic_mode_raw is not None else 'off'
    traffic_file = Path(traffic_file_raw) if traffic_file_raw is not None else None
    ca_raw = getattr(args, 'ca_file', None)
    ca_file = Path(ca_raw) if ca_raw is not None else None
    if ca_file is not None and not ca_file.is_file():
        raise ConfigError(f'--ca-file is not a readable file: {ca_file}')
    run_as_raw = getattr(args, 'run_as', None)
    run_as = parse_run_as(run_as_raw) if run_as_raw else None
    max_body_size = int(getattr(args, 'max_body_size', DEFAULT_MAX_BODY_SIZE))
    if max_body_size < 1:
        raise ConfigError('--max-body-size must be positive')
    connect_timeout = float(getattr(args, 'connect_timeout', DEFAULT_CONNECT_TIMEOUT))
    response_timeout = float(getattr(args, 'response_timeout', DEFAULT_RESPONSE_TIMEOUT))
    if connect_timeout <= 0 or response_timeout <= 0:
        raise ConfigError('timeouts must be positive')
    return AppConfig(
        command=command,
        listen_host=listen_host,
        listen_port=listen_port,
        manage_network=manage_network,
        interface=interface,
        target=target,
        run_as=run_as,
        kill_sessions=bool(getattr(args, 'kill_sessions', False)),
        max_body_size=max_body_size,
        connect_timeout=connect_timeout,
        response_timeout=response_timeout,
        ca_file=ca_file,
        traffic_log_mode=traffic_mode,
        traffic_log_file=traffic_file,
        state_dir=Path(getattr(args, 'state_dir', DEFAULT_STATE_DIR)),
        link_ttl_seconds=DEFAULT_LINK_TTL_SECONDS,
        link_limit=DEFAULT_LINK_LIMIT,
        nft_executable=str(getattr(args, 'nft_executable', 'nft')),
        verbose=int(getattr(args, 'verbose', 0)),
        worker=bool(getattr(args, 'worker', False)),
    )


def parse_run_as(value: str) -> tuple[int, int]:
    """Parse ``user``, ``uid``, or ``user:group`` into ``(uid, gid)``."""
    user_part: str
    group_part: str | None
    if ':' in value:
        user_part, group_part = value.split(':', 1)
    else:
        user_part, group_part = value, None
    uid = _resolve_uid(user_part)
    gid = pwd.getpwuid(uid).pw_gid if group_part is None or group_part == '' else _resolve_gid(group_part)
    return uid, gid


def validate_interface_name(name: str) -> None:
    """Reject interface names that cannot be used in nftables matches."""
    if name == '' or len(name) > INTERFACE_NAME_RE_MAX:
        raise ConfigError(f'invalid interface name: {name!r}')
    if any(ch in name for ch in '/\\ \t\n\r\x00'):
        raise ConfigError(f'invalid interface name: {name!r}')
    if name in {'.', '..'}:
        raise ConfigError(f'invalid interface name: {name!r}')


def interface_exists(name: str) -> bool:
    """Return True if ``name`` is a current kernel interface."""
    return any(entry[1] == name for entry in socket.if_nameindex())


def interface_ipv4(name: str) -> IPv4Address:
    """Return the IPv4 address of ``name`` using SIOCGIFADDR."""
    import fcntl
    import struct

    validate_interface_name(name)
    if not interface_exists(name):
        raise ConfigError(f'unknown interface: {name}')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack('256s', name.encode('ascii', errors='strict')[:15])
        result = fcntl.ioctl(sock.fileno(), 0x8915, packed)
        addr = socket.inet_ntoa(result[20:24])
    except OSError as exc:
        raise ConfigError(f'interface {name} has no IPv4 address') from exc
    finally:
        sock.close()
    return IPv4Address(addr)


def _resolve_uid(value: str) -> int:
    if value.isdigit():
        return int(value)
    try:
        return pwd.getpwnam(value).pw_uid
    except KeyError as exc:
        raise ConfigError(f'unknown user: {value}') from exc


def _resolve_gid(value: str) -> int:
    if value.isdigit():
        return int(value)
    try:
        return grp.getgrnam(value).gr_gid
    except KeyError as exc:
        raise ConfigError(f'unknown group: {value}') from exc


def version_string() -> str:
    """Return the public version string."""
    return __version__
