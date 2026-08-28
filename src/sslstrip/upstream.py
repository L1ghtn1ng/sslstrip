"""Shared Twisted Agent, verified TLS policy, and connection pool."""

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from tempfile import SpooledTemporaryFile
from typing import BinaryIO, cast, override

from OpenSSL import SSL
from twisted.internet._sslverify import IOpenSSLTrustRoot
from twisted.internet.defer import Deferred, succeed
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator, IReactorTime
from twisted.internet.protocol import Protocol, connectionDone
from twisted.internet.ssl import optionsForClientTLS
from twisted.python.failure import Failure
from twisted.web.client import Agent, HTTPConnectionPool, PartialDownloadError, PotentialDataLoss, ResponseDone
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer, IPolicyForHTTPS
from zope.interface import implementer

from sslstrip.errors import ProxyTimeoutError
from sslstrip.twisted_types import AgentResponse, BodyConsumer


@implementer(IOpenSSLTrustRoot)
class LabTrustRoot:
    """System trust store plus optional extra lab CA certificates."""

    def __init__(self, ca_file: Path | None) -> None:
        self._ca_file = ca_file

    def _addCACertsToContext(self, context: SSL.Context) -> None:
        context.set_default_verify_paths()
        if self._ca_file is not None:
            context.load_verify_locations(cafile=os.fspath(self._ca_file))


@implementer(IPolicyForHTTPS)
class LabTlsPolicy:
    """``IPolicyForHTTPS`` using system CAs and optional ``--ca-file`` PEMs."""

    def __init__(self, ca_file: Path | None) -> None:
        self._trust = LabTrustRoot(ca_file)

    def creatorForNetloc(self, hostname: bytes, port: int) -> IOpenSSLClientConnectionCreator:
        del port
        host = hostname.decode('idna')
        return optionsForClientTLS(host, trustRoot=cast('IOpenSSLTrustRoot', self._trust))


@implementer(IBodyProducer)
class BytesBodyProducer:
    """In-memory body producer for Agent.request."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.length: int = len(body)

    def startProducing(self, consumer: BodyConsumer) -> Deferred[None]:
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self) -> None:
        return None

    def stopProducing(self) -> None:
        return None


def build_agent(reactor: IReactorTime, *, connect_timeout: float, ca_file: Path | None) -> tuple[Agent, HTTPConnectionPool]:
    """Create a pooled Agent that verifies TLS."""
    pool = HTTPConnectionPool(reactor, persistent=True)
    policy = LabTlsPolicy(ca_file)
    agent = Agent(reactor, contextFactory=policy, pool=pool, connectTimeout=connect_timeout)
    return agent, pool


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    """Upstream response metadata and its replayable body."""

    code: int
    phrase: bytes
    headers: list[tuple[str, str]]
    body: bytes | ResponseBody


class ResponseBody:
    """A response body held in a bounded-memory spool."""

    def __init__(self, stream: BinaryIO, size: int) -> None:
        self._stream = stream
        self.size = size

    def read(self) -> bytes:
        self._stream.seek(0)
        return self._stream.read()

    def __iter__(self) -> Iterator[bytes]:
        self._stream.seek(0)
        while chunk := self._stream.read(65536):
            yield chunk

    def close(self) -> None:
        self._stream.close()


class _ResponseBodyReceiver(Protocol):
    def __init__(self, max_in_memory: int) -> None:
        self._stream = cast(
            'BinaryIO',
            SpooledTemporaryFile(max_size=max_in_memory, mode='w+b'),  # noqa: SIM115 -- closed by the request owner
        )
        self._size = 0
        self.finished: Deferred[ResponseBody] = Deferred(self._cancel)

    @override
    def dataReceived(self, data: bytes) -> None:
        self._stream.write(data)
        self._size += len(data)

    @override
    def connectionLost(self, reason: Failure = connectionDone) -> None:
        if self.finished.called:
            return
        if reason.check(ResponseDone, PotentialDataLoss, PartialDownloadError):
            self._stream.seek(0)
            self.finished.callback(ResponseBody(self._stream, self._size))
            return
        self._stream.close()
        self.finished.errback(reason)

    def _cancel(self, deferred: Deferred[ResponseBody]) -> None:
        del deferred
        self._stream.close()
        abort = getattr(getattr(self, 'transport', None), 'abortConnection', None)
        if abort is not None:
            abort()


async def request_upstream(
    agent: Agent,
    reactor: IReactorTime,
    *,
    method: bytes,
    url: str,
    headers: list[tuple[str, str]],
    body: bytes,
    timeout: float,
    max_body_size: int,
) -> UpstreamResponse:
    """Issue one upstream request and spool the response body.

    ``timeout`` bounds each phase of the exchange: waiting for response
    headers and reading the response body.
    """
    producer = cast('IBodyProducer | None', BytesBodyProducer(body) if body else None)
    header_map: dict[str, list[str]] = {}
    for name, value in headers:
        header_map.setdefault(name, []).append(value)
    tw_headers = Headers({name: values for name, values in header_map.items()})
    deferred = agent.request(method, url.encode('ascii'), tw_headers, producer)
    timed = deferred.addTimeout(timeout, reactor)
    try:
        raw = await timed
    except TimeoutError as exc:
        raise ProxyTimeoutError('upstream response timed out') from exc
    response = cast('AgentResponse', raw)
    receiver = _ResponseBodyReceiver(max_body_size)
    response.deliverBody(receiver)
    body_deferred = receiver.finished.addTimeout(timeout, reactor)
    try:
        response_body = await body_deferred
    except TimeoutError as exc:
        raise ProxyTimeoutError('upstream response timed out') from exc
    return UpstreamResponse(
        code=response.code,
        phrase=response.phrase,
        headers=_pairs_from_response(response),
        body=response_body,
    )


def _pairs_from_response(response: AgentResponse) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for name, values in response.headers.getAllRawHeaders():
        decoded_name = name.decode('latin-1') if isinstance(name, bytes) else str(name)
        for value in values:
            decoded_value = value.decode('latin-1') if isinstance(value, bytes) else str(value)
            pairs.append((decoded_name, decoded_value))
    return pairs
