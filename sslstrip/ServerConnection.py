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
import gzip
import logging
import re
from io import BytesIO

from twisted.web.http import HTTPClient

from .URLMonitor import URLMonitor


class ServerConnection(HTTPClient):
    """The server connection is where we do the bulk of the stripping."""

    urlExpression = re.compile(r'(https://[\w\d:#@%/;$()~_?\+-=\\\.&]*)', re.IGNORECASE)
    urlType = re.compile(r'https://', re.IGNORECASE)
    urlExplicitPort = re.compile(r'https://([a-zA-Z0-9.]+):[0-9]+/', re.IGNORECASE)

    def __init__(self, command, uri, postData, headers, client):
        super().__init__()
        self.command = command
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.client = client
        self.urlMonitor = URLMonitor.get_instance()
        self.isImageRequest = False
        self.isCompressed = False
        self.contentLength = None
        self.shutdownComplete = False

    @property
    def log_level(self):
        return logging.DEBUG

    @property
    def post_prefix(self):
        return 'POST'

    def send_request(self):
        logging.log(self.log_level, f'Sending Request: {self.command} {self.uri}')
        self.sendCommand(self.command, self.uri)

    def send_headers(self):
        for header, value in self.headers.items():
            logging.log(self.log_level, f'Sending header: {header} : {value}')
            self.sendHeader(header, value)
        self.endHeaders()

    def send_post_data(self):
        logging.warning(f'{self.post_prefix} Data ({self.headers["host"]}):\n{self.postData!s}')
        self.transport.write(self.postData)

    def connectionMade(self):
        logging.log(self.log_level, 'HTTP connection made.')
        self.send_request()
        self.send_headers()
        if self.command == 'POST':
            self.send_post_data()

    def handleStatus(self, version, code, message):
        logging.log(self.log_level, f'Got server response: {version} {code} {message}')
        self.client.setResponseCode(int(code), message)

    def handleHeader(self, key, value):
        logging.log(self.log_level, f'Got server header: {key}:{value}')
        value = self.replace_secure_links(value) if key.lower() == 'location' else value
        self.set_image_request(value) if key.lower() == 'content-type' else value
        self.set_compressed(value) if key.lower() == 'content-encoding' else value
        self.contentLength = value if key.lower() == 'content-length' else self.contentLength
        if key.lower() in ['set-cookie', 'content-length']:
            self.client.responseHeaders.addRawHeader(key, value)
        else:
            self.client.setHeader(key, value)

    def set_image_request(self, value):
        if 'image' in value:
            self.isImageRequest = True
            logging.debug('Response is image content, not scanning...')

    def set_compressed(self, value):
        if 'gzip' in value:
            logging.debug('Response is compressed...')
            self.isCompressed = True

    def handleEndHeaders(self):
        if self.isImageRequest and self.contentLength is not None:
            self.client.setHeader('Content-Length', self.contentLength)
        if not self.length:
            self.shutdown()

    def handleResponsePart(self, data):
        self.client.write(data) if self.isImageRequest else super().handleResponsePart(data)

    def handleResponseEnd(self):
        self.shutdown() if self.isImageRequest else super().handleResponseEnd()

    def handle_response(self, data):
        if self.isCompressed:
            logging.debug('Decompressing content...')
            data = gzip.GzipFile('', 'rb', 9, BytesIO(data)).read()

        logging.log(self.log_level, f'Read from server:\n{data}')

        data = self.replace_secure_links(data)

        if self.contentLength is not None:
            self.client.setHeader('Content-Length', len(data))

        self.client.write(data)
        self.shutdown()

    def replace_secure_links(self, data):
        iterator = re.finditer(self.urlExpression, data)

        for match in iterator:
            url = match.group()
            logging.debug(f'Found secure reference: {url}')
            url = url.replace('https://', 'http://', 1).replace('&amp;', '&')
            self.urlMonitor.add_secure_link(self.client.getClientIP(), url)

        data = self.urlExplicitPort.sub(r'http://\1/', data)
        return self.urlType.sub('http://', data)

    def shutdown(self):
        if not self.shutdownComplete:
            self.shutdownComplete = True
            self.client.finish()
            self.transport.loseConnection()
