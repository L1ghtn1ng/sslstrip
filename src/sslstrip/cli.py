"""Public command-line entry point."""

import sys

from twisted.internet import reactor

from sslstrip.config import ConfigError, parse_config
from sslstrip.doctor import format_report, run_doctor
from sslstrip.logs import TrafficLogError, configure_logging
from sslstrip.proxy import run_reactor, start_proxy
from sslstrip.supervisor import cleanup_managed, run_managed


def main(arguments: list[str] | None = None) -> int:
    """Run sslstrip. Returns a process exit code."""
    try:
        parsed = parse_config(arguments)
    except ConfigError as exc:
        print(f'sslstrip: {exc}', file=sys.stderr)
        return 2
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(str(code), file=sys.stderr)
        return 2
    configure_logging(parsed.verbose)
    try:
        if parsed.command == 'doctor':
            results = run_doctor(parsed)
            print(format_report(results))
            return 0 if all(item.ok for item in results) else 1
        if parsed.command == 'cleanup':
            return cleanup_managed(parsed)
        if parsed.manage_network and not parsed.worker:
            return run_managed(parsed)
        start_proxy(reactor, parsed)
        run_reactor(reactor)
        return 0
    except ConfigError as exc:
        print(f'sslstrip: {exc}', file=sys.stderr)
        return 2
    except TrafficLogError as exc:
        print(f'sslstrip: {exc}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
