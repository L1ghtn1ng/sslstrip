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

import re
from typing import ClassVar


class URLMonitor:
    """
    The URL monitor maintains a set of (client, url) tuples that correspond to requests which the
    server is expecting over SSL.  It also keeps track of secure favicon urls.
    """

    # Start the arms race, and end up here...
    javascriptTrickery: ClassVar[list] = [re.compile(r'http://.+\.etrade\.com/javascript/omntr/tc_targeting\.html')]
    _instance = None

    def __init__(self):
        self.strippedURLs = set()
        self.strippedURLPorts = {}
        self.faviconReplacement = False

    def is_secure_link(self, client, url):
        for expression in URLMonitor.javascriptTrickery:
            if re.match(expression, url):
                return True

        return (client, url) in self.strippedURLs

    def get_secure_port(self, client, url):
        if (client, url) in self.strippedURLs:
            return self.strippedURLPorts[(client, url)]
        else:
            return 443

    def add_secure_link(self, client, url):
        methodIndex = url.find('//') + 2
        method = url[0:methodIndex]

        pathIndex = url.find('/', methodIndex)
        host = url[methodIndex:pathIndex]
        path = url[pathIndex:]

        port = 443
        portIndex = host.find(':')

        if portIndex != -1:
            host = host[0:portIndex]
            port = host[portIndex + 1 :]
            if not port.isdigit():
                port = 443

        url = method + host + path

        self.strippedURLs.add((client, url))
        self.strippedURLPorts[(client, url)] = int(port)

    def set_favicon_spoofing(self, favicon_spoofing):
        self.faviconSpoofing = favicon_spoofing

    def is_favicon_spoofing(self):
        return self.faviconSpoofing

    def is_secure_favicon(self, client, url):
        return (self.faviconSpoofing is True) and (url.find('favicon-x-favicon-x.ico') != -1)

    @staticmethod
    def get_instance():
        if URLMonitor._instance is None:
            URLMonitor._instance = URLMonitor()

        return URLMonitor._instance
