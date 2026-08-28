"""Read-only environment checks for sslstrip."""

import importlib
import os
import shutil
import socket
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from sslstrip.config import TRUSTED_STICKY_DIRS, AppConfig, interface_exists, interface_ipv4, validate_interface_name
from sslstrip.nftables import run_nft


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One doctor check."""

    name: str
    ok: bool
    detail: str


def run_doctor(config: AppConfig) -> list[CheckResult]:
    """Execute all read-only checks."""
    return [
        _check_python(),
        _check_dependency('twisted'),
        _check_dependency('brotli'),
        _check_zstd(),
        _check_interface(config),
        _check_nft(config),
        _check_privilege(config),
        _check_port(config),
        _check_target(config),
        _check_state_dir(config),
        _check_ca_file(config),
    ]


def format_report(results: list[CheckResult]) -> str:
    """Render doctor results as text."""
    lines: list[str] = []
    for result in results:
        status = 'ok' if result.ok else 'FAIL'
        lines.append(f'{status:4} {result.name}: {result.detail}')
    return '\n'.join(lines)


def _check_python() -> CheckResult:
    version = sys.version_info
    ok = version >= (3, 14)
    return CheckResult('python', ok, f'{version.major}.{version.minor}.{version.micro}')


def _check_dependency(name: str) -> CheckResult:
    try:
        module = importlib.import_module(name)
    except ImportError as exc:
        return CheckResult(name, False, str(exc))
    version = getattr(module, '__version__', 'present')
    return CheckResult(name, True, str(version))


def _check_zstd() -> CheckResult:
    try:
        import compression.zstd as zstd
    except ImportError as exc:
        return CheckResult('compression.zstd', False, str(exc))
    del zstd
    return CheckResult('compression.zstd', True, 'stdlib')


def _check_interface(config: AppConfig) -> CheckResult:
    if config.interface is None:
        return CheckResult('interface', True, 'not required')
    try:
        validate_interface_name(config.interface)
    except Exception as exc:
        return CheckResult('interface', False, str(exc))
    if not interface_exists(config.interface):
        return CheckResult('interface', False, f'{config.interface} not found')
    try:
        addr = interface_ipv4(config.interface)
    except Exception as exc:
        return CheckResult('interface', False, str(exc))
    return CheckResult('interface', True, f'{config.interface} {addr}')


def _check_nft(config: AppConfig) -> CheckResult:
    path = shutil.which(config.nft_executable)
    if path is None and not Path(config.nft_executable).exists():
        return CheckResult('nftables', False, f'{config.nft_executable!r} not found')
    result = run_nft(config.nft_executable, ['--version'])
    detail = result.stdout.decode('utf-8', errors='replace').strip() or result.stderr.decode('utf-8', errors='replace').strip()
    ok = result.returncode == 0
    return CheckResult('nftables', ok, detail or path or config.nft_executable)


def _check_privilege(config: AppConfig) -> CheckResult:
    euid = os.geteuid()
    managed = config.interface is not None and config.target is not None
    return CheckResult('privilege', not managed or euid == 0, f'euid={euid}')


def _check_port(config: AppConfig) -> CheckResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((config.listen_host, config.listen_port))
    except OSError as exc:
        return CheckResult('port', False, f'{config.listen_host}:{config.listen_port} {exc}')
    finally:
        sock.close()
    return CheckResult('port', True, f'{config.listen_host}:{config.listen_port} available')


def _check_target(config: AppConfig) -> CheckResult:
    if config.target is None:
        return CheckResult('target', True, 'not required')
    return CheckResult('target', True, str(config.target))


def _check_state_dir(config: AppConfig) -> CheckResult:
    path = config.state_dir
    ancestor_issue = _state_ancestor_issue(path)
    if ancestor_issue is not None:
        return CheckResult('state-dir', False, ancestor_issue)
    try:
        details = path.lstat()
    except FileNotFoundError:
        details = None
    if details is not None:
        if not stat.S_ISDIR(details.st_mode):
            return CheckResult('state-dir', False, f'{path} is not a directory')
        expected_uid = os.geteuid()
        if details.st_uid != expected_uid:
            return CheckResult('state-dir', False, f'{path} is not owned by uid {expected_uid}')
        if stat.S_IMODE(details.st_mode) != 0o700:
            return CheckResult('state-dir', False, f'{path} must have mode 0700')
        return CheckResult('state-dir', True, f'{path} exists')
    parent = path.parent
    if parent.exists() and os.access(parent, os.W_OK):
        return CheckResult('state-dir', True, f'{path} can be created')
    if parent.exists():
        return CheckResult('state-dir', False, f'{parent} is not writable')
    return CheckResult('state-dir', True, f'{path} (parent missing; root can create)')


def _state_ancestor_issue(path: Path) -> str | None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:-1]:
        current /= component
        try:
            details = current.lstat()
        except FileNotFoundError:
            break
        if not stat.S_ISDIR(details.st_mode):
            return f'{current} is not a directory'
        mode = stat.S_IMODE(details.st_mode)
        trusted_owner = details.st_uid in {0, os.geteuid()}
        shared_system_directory = current in TRUSTED_STICKY_DIRS
        trusted_sticky_directory = bool(details.st_mode & stat.S_ISVTX) and (trusted_owner or shared_system_directory)
        if not trusted_owner and not trusted_sticky_directory:
            return f'{current} has an unsafe owner'
        if mode & 0o022 and not trusted_sticky_directory:
            return f'{current} has unsafe writable permissions'
    return None


def _check_ca_file(config: AppConfig) -> CheckResult:
    if config.ca_file is None:
        return CheckResult('ca-file', True, 'system trust store')
    if not config.ca_file.is_file():
        return CheckResult('ca-file', False, f'{config.ca_file} is not a file')
    text = config.ca_file.read_text(encoding='utf-8', errors='replace')
    if 'BEGIN CERTIFICATE' not in text:
        return CheckResult('ca-file', False, 'file does not contain a PEM certificate')
    return CheckResult('ca-file', True, str(config.ca_file))
