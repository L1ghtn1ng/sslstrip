"""
This file is licensed under the GNU General Public License version 3.
Copyright (c) 2004-2009 Moxie Marlinspike
"""

import logging

from twisted.internet.protocol import ClientFactory


class ServerConnectionFactory(ClientFactory):
    """
    This class is used to create a connection to the server.
    """

    def __init__(self, command, uri, postData, headers, client):
        """
        Initialize the ServerConnectionFactory with remote server details,
        as well as a client reference for proxying requests.
        """
        self.command = command
        self.uri = uri
        self.postData = postData
        self.headers = headers
        self.client = client

    def buildProtocol(self, addr):
        """
        Build protocol creates an instance of the protocol to be used for the connection.
        """
        return self.protocol(self.command, self.uri, self.postData, self.headers, self.client)

    def clientConnectionFailed(self, connector, reason):
        """
        This function is called if connection to the server fails.
        """
        logging.debug('Server connection failed.')
        destination = connector.getDestination()

        # Retry connection with SSL if not on port 443
        if destination.port != 443:
            logging.debug('Retrying via SSL')
            self.client.proxyViaSSL(
                self.headers['host'],
                self.command,
                self.uri,
                self.postData,
                self.headers,
                443,
            )
        else:
            self.client.finish()
