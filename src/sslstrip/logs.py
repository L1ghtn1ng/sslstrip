"""Operational logging to stderr and gated unredacted traffic logs."""

import logging
import os
import stat
import sys
from codecs import getincrementaldecoder
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Literal, TextIO

TrafficMode = Literal['off', 'post', 'secure', 'all']

TRAFFIC_WARNING = (
    'WARNING: unredacted traffic logging is enabled. The traffic log file will contain '
    'credentials, cookies, and request/response bodies. Restrict access to this file.'
)


class TrafficLogError(ValueError):
    """The traffic log path is missing, a symlink, or not a regular file."""


def configure_logging(verbose: int) -> None:
    """Send operational logs to stderr. ``verbose`` 0=WARNING, 1=INFO, 2+=DEBUG."""
    if verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger = logging.getLogger('sslstrip')
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


class TrafficLog:
    """Write unredacted traffic only when both mode and file are configured."""

    def __init__(self, mode: TrafficMode, path: Path | None) -> None:
        self.mode = mode
        self.path = path
        self._fp: TextIO | None = None
        if mode != 'off':
            if path is None:
                raise TrafficLogError('traffic logging requires --traffic-log-file')
            self._fp = open_traffic_log(path)
            print(TRAFFIC_WARNING, file=sys.stderr)

    def close(self) -> None:
        if self._fp is not None:
            self._fp.close()
            self._fp = None

    def enabled_for(self, *, method: str, secure: bool) -> bool:
        if self.mode == 'off' or self._fp is None:
            return False
        if self.mode == 'all':
            return True
        if self.mode == 'secure':
            return secure
        return method.upper() == 'POST'

    def write(
        self,
        *,
        direction: str,
        method: str,
        url: str,
        secure: bool,
        headers: Mapping[str, str] | list[tuple[str, str]],
        body: bytes | Iterable[bytes],
    ) -> None:
        if not self.enabled_for(method=method, secure=secure) or self._fp is None:
            return
        scheme = 'https' if secure else 'http'
        self._fp.write(f'--- {direction} {method} {url} ({scheme}) ---\n')
        items = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        for name, value in items:
            self._fp.write(f'{name}: {value}\n')
        self._fp.write('\n')
        if isinstance(body, bytes):
            self._fp.write(body.decode('utf-8', errors='replace'))
        else:
            decoder = getincrementaldecoder('utf-8')(errors='replace')
            for chunk in body:
                self._fp.write(decoder.decode(chunk))
            self._fp.write(decoder.decode(b'', final=True))
        self._fp.write('\n')
        self._fp.flush()


def open_traffic_log(path: Path) -> TextIO:
    """Create or open a regular, non-symlink 0600 traffic log file."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    try:
        existing = path.lstat()
    except FileNotFoundError:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, 'w', encoding='utf-8')
    if stat.S_ISLNK(existing.st_mode):
        raise TrafficLogError(f'refusing to write traffic log through symlink: {path}')
    if not stat.S_ISREG(existing.st_mode):
        raise TrafficLogError(f'traffic log is not a regular file: {path}')
    fd = os.open(path, flags)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'w', encoding='utf-8')
