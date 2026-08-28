"""Unit tests for Agent helpers that do not need a live network."""

from pathlib import Path
from typing import cast

from tests.certs import write_lab_ca_and_leaf
from twisted.internet.interfaces import ITransport
from twisted.python.failure import Failure
from twisted.web.client import PartialDownloadError, PotentialDataLoss, ResponseDone

from sslstrip.upstream import BytesBodyProducer, LabTlsPolicy, _ResponseBodyReceiver


def test_bytes_body_producer_writes() -> None:
    chunks: list[bytes] = []

    class Consumer:
        def write(self, data: bytes) -> None:
            chunks.append(data)

    producer = BytesBodyProducer(b'hello')
    assert producer.length == 5
    producer.startProducing(Consumer())
    producer.pauseProducing()
    producer.stopProducing()
    assert chunks == [b'hello']


def test_tls_policy_without_ca() -> None:
    policy = LabTlsPolicy(None)
    creator = policy.creatorForNetloc(b'example.com', 443)
    assert creator is not None


def test_tls_policy_with_ca(tmp_path: Path) -> None:
    ca, _cert, _key = write_lab_ca_and_leaf(tmp_path, '127.0.0.1')
    policy = LabTlsPolicy(ca)
    creator = policy.creatorForNetloc(b'127.0.0.1', 443)
    assert creator is not None


def test_response_receiver_spools_and_streams_large_body() -> None:
    receiver = _ResponseBodyReceiver(4)
    bodies = []
    receiver.finished.addCallback(bodies.append)
    receiver.dataReceived(b'abc')
    receiver.dataReceived(b'def')
    assert getattr(receiver._stream, '_rolled', False)
    receiver.connectionLost(Failure(ResponseDone()))
    body = bodies[0]
    assert body.size == 6
    assert body.read() == b'abcdef'
    assert b''.join(body) == b'abcdef'
    body.close()


def test_response_receiver_accepts_close_delimited_completion() -> None:
    for reason in (PotentialDataLoss(), PartialDownloadError(200, b'OK', b'body')):
        receiver = _ResponseBodyReceiver(16)
        bodies = []
        receiver.finished.addCallback(bodies.append)
        receiver.dataReceived(b'body')
        receiver.connectionLost(Failure(reason))
        assert bodies[0].read() == b'body'
        bodies[0].close()


def test_response_receiver_reports_transport_failure() -> None:
    receiver = _ResponseBodyReceiver(16)
    failures = []
    receiver.finished.addErrback(failures.append)
    receiver.connectionLost(Failure(ConnectionError('broken')))
    assert failures[0].check(ConnectionError)


def test_response_receiver_cancellation_aborts_transport() -> None:
    class Transport:
        aborted = False

        def abortConnection(self) -> None:
            self.aborted = True

    receiver = _ResponseBodyReceiver(16)
    transport = Transport()
    receiver.transport = cast('ITransport', transport)
    receiver.finished.addErrback(lambda _failure: None)
    receiver.finished.cancel()
    receiver.connectionLost(Failure(PotentialDataLoss()))
    assert transport.aborted
