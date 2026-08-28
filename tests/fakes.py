"""In-memory fakes for unit tests."""

from collections.abc import Iterator
from io import BytesIO
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal

from sslstrip.config import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_LINK_LIMIT,
    DEFAULT_LINK_TTL_SECONDS,
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_RESPONSE_TIMEOUT,
    DEFAULT_STATE_DIR,
    AppConfig,
)
from sslstrip.logs import TrafficMode
from sslstrip.twisted_types import FileLike, PullProducer


class FakeHeaders:
    """RawHeaders implementation backed by a list of pairs."""

    def __init__(self, items: list[tuple[bytes, list[bytes]]] | None = None) -> None:
        self.items: list[tuple[bytes, list[bytes]]] = items if items is not None else []

    def getAllRawHeaders(self) -> Iterator[tuple[bytes, list[bytes]]]:
        return iter(self.items)

    def addRawHeader(self, name: bytes | str, value: bytes | str) -> None:
        encoded_name = name if isinstance(name, bytes) else name.encode('latin-1')
        encoded_value = value if isinstance(value, bytes) else value.encode('latin-1')
        for key, values in self.items:
            if key.lower() == encoded_name.lower():
                values.append(encoded_value)
                return
        self.items.append((encoded_name, [encoded_value]))

    def removeHeader(self, name: bytes | str) -> None:
        encoded_name = name if isinstance(name, bytes) else name.encode('latin-1')
        self.items = [(key, values) for key, values in self.items if key.lower() != encoded_name.lower()]

    def setRawHeaders(self, name: bytes | str, values: list[bytes] | list[str]) -> None:
        self.removeHeader(name)
        for value in values:
            self.addRawHeader(name, value)


class FakeRequest:
    """ClientRequestLike used by request-handler unit tests."""

    def __init__(
        self,
        *,
        method: bytes = b'GET',
        uri: bytes = b'/',
        host: str | None = 'example.com',
        clientproto: bytes = b'HTTP/1.1',
        body: bytes = b'',
        extra_headers: list[tuple[bytes, bytes]] | None = None,
        client_ip: str = '192.0.2.10',
    ) -> None:
        self.method = method
        self.uri = uri
        self.clientproto = clientproto
        self.content: FileLike | None = BytesIO(body)
        self.requestHeaders = FakeHeaders()
        self.responseHeaders = FakeHeaders()
        self._client_ip = client_ip
        self.code = 200
        self.body_chunks: list[bytes] = []
        self.finished = False
        self._producer: PullProducer | None = None
        if host is not None:
            self.requestHeaders.addRawHeader(b'Host', host.encode('latin-1'))
        if extra_headers:
            for name, value in extra_headers:
                self.requestHeaders.addRawHeader(name, value)

    def getHeader(self, key: str) -> str | None:
        encoded = key.encode('latin-1')
        for name, values in self.requestHeaders.items:
            if name.lower() == encoded.lower():
                return values[-1].decode('latin-1')
        return None

    def getClientIP(self) -> str | None:
        return self._client_ip

    def setResponseCode(self, code: int, message: bytes | None = None) -> None:
        del message
        self.code = code

    def setHeader(self, name: bytes | str, value: bytes | str) -> None:
        self.responseHeaders.removeHeader(name)
        self.responseHeaders.addRawHeader(name, value)

    def write(self, data: bytes) -> None:
        self.body_chunks.append(data)

    def finish(self) -> None:
        self.finished = True

    def registerProducer(self, producer: PullProducer, streaming: bool) -> None:
        assert not streaming
        self._producer = producer
        while self._producer is producer:
            producer.resumeProducing()

    def unregisterProducer(self) -> None:
        self._producer = None

    @property
    def body(self) -> bytes:
        return b''.join(self.body_chunks)


def sample_config(
    *,
    command: Literal['run', 'doctor', 'cleanup'] = 'run',
    listen_host: str = DEFAULT_LISTEN_HOST,
    listen_port: int = DEFAULT_LISTEN_PORT,
    manage_network: bool = False,
    interface: str | None = None,
    target: IPv4Address | None = None,
    run_as: tuple[int, int] | None = None,
    kill_sessions: bool = False,
    max_body_size: int = DEFAULT_MAX_BODY_SIZE,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
    ca_file: Path | None = None,
    traffic_log_mode: TrafficMode = 'off',
    traffic_log_file: Path | None = None,
    state_dir: Path = DEFAULT_STATE_DIR,
    link_ttl_seconds: float = DEFAULT_LINK_TTL_SECONDS,
    link_limit: int = DEFAULT_LINK_LIMIT,
    nft_executable: str = 'nft',
    verbose: int = 0,
    worker: bool = False,
) -> AppConfig:
    """Build an AppConfig for tests."""
    return AppConfig(
        command=command,
        listen_host=listen_host,
        listen_port=listen_port,
        manage_network=manage_network,
        interface=interface,
        target=target,
        run_as=run_as,
        kill_sessions=kill_sessions,
        max_body_size=max_body_size,
        connect_timeout=connect_timeout,
        response_timeout=response_timeout,
        ca_file=ca_file,
        traffic_log_mode=traffic_log_mode,
        traffic_log_file=traffic_log_file,
        state_dir=state_dir,
        link_ttl_seconds=link_ttl_seconds,
        link_limit=link_limit,
        nft_executable=nft_executable,
        verbose=verbose,
        worker=worker,
    )
