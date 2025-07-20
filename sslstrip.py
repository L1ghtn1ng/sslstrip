#!/usr/bin/env python3

"""sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks."""

__author__ = 'Moxie Marlinspike'
__email__ = 'moxie@thoughtcrime.org'
__license__ = """
Copyright (c) 2004-2009 Moxie Marlinspike <moxie@thoughtcrime.org>
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import argparse
import logging
import sys

from twisted.internet import endpoints, reactor
from twisted.web import server

from sslstrip.CookieCleaner import CookieCleaner
from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor


class SSLStripConfig:
    VERSION = '4.0'
    DEFAULT_LOGFILE = 'sslstrip.log'
    DEFAULT_LOGLEVEL = logging.WARNING
    DEFAULT_LISTEN_PORT = 10000
    DEFAULT_SPOOF_FAVICON = False
    DEFAULT_KILL_SESSIONS = False


def initialize_logger(logFile: str, logLevel: int) -> None:
    try:
        logging.basicConfig(level=logLevel, format='%(asctime)s %(levelname)s %(message)s', filename=logFile, filemode='w')
    except Exception as e:
        print(f'Failed to initialize logger: {e}')
        sys.exit(1)


def start_reactor(listenPort: int, spoofFavicon: bool, killSessions: bool) -> None:
    try:
        URLMonitor.get_instance().set_favicon_spoofing(spoofFavicon)
        CookieCleaner.getInstance().set_enabled(killSessions)

        strippingFactory = server.Site(StrippingProxy())
        endpoint = endpoints.TCP4ServerEndpoint(reactor, listenPort)
        endpoint.listen(strippingFactory)

        print(f'\nsslstrip {SSLStripConfig.VERSION} by Moxie Marlinspike running...')
        print(f'Listening on port {listenPort}')
        reactor.run()
    except Exception as e:
        logging.error(f'Failed to start reactor: {e}')
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='sslstrip - SSL MITM stripping tool', formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-w', '--write', default=SSLStripConfig.DEFAULT_LOGFILE, help='Specify file to log to')
    parser.add_argument('-p', '--post', default=False, action='store_true', help='Log only SSL POSTs')
    parser.add_argument('-s', '--ssl', default=False, action='store_true', help='Log all SSL traffic to and from server')
    parser.add_argument('-a', '--all', default=False, action='store_true', help='Log all SSL and HTTP traffic to and from server')
    parser.add_argument('-l', '--listen', type=int, default=SSLStripConfig.DEFAULT_LISTEN_PORT, help='Port to listen on')
    parser.add_argument(
        '-f',
        '--favicon',
        default=SSLStripConfig.DEFAULT_SPOOF_FAVICON,
        action='store_true',
        help='Substitute a lock favicon on secure requests',
    )
    parser.add_argument(
        '-k',
        '--killsessions',
        default=SSLStripConfig.DEFAULT_KILL_SESSIONS,
        action='store_true',
        help='Kill sessions in progress',
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Set log level based on verbosity flags
    log_level = SSLStripConfig.DEFAULT_LOGLEVEL
    if args.all:
        log_level = logging.DEBUG
    elif args.ssl:
        log_level = logging.INFO
    elif args.post:
        log_level = logging.WARNING

    initialize_logger(args.write, log_level)
    start_reactor(args.listen, args.favicon, args.killsessions)


if __name__ == '__main__':
    main()
