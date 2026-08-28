"""Typed Protocols for the Twisted request/response boundary."""

from collections.abc import Iterator, Sequence
from typing import Protocol, runtime_checkable


@runtime_checkable
class FileLike(Protocol):
    """Seekable byte stream used for the client request body."""

    def read(self, n: int = ..., /) -> bytes: ...

    def seek(self, offset: int, whence: int = 0, /) -> int: ...


@runtime_checkable
class RawHeaders(Protocol):
    """Subset of Twisted ``Headers`` used by the request adapter."""

    def getAllRawHeaders(self) -> Iterator[tuple[bytes, Sequence[bytes]]]: ...

    def addRawHeader(self, name: bytes | str, value: bytes | str) -> None: ...

    def removeHeader(self, name: bytes | str) -> None: ...

    def setRawHeaders(self, name: bytes | str, values: list[bytes] | list[str]) -> None: ...


@runtime_checkable
class ClientRequestLike(Protocol):
    """Subset of ``twisted.web.http.Request`` used by request handling."""

    method: bytes
    uri: bytes
    clientproto: bytes
    content: FileLike | None

    @property
    def requestHeaders(self) -> RawHeaders: ...

    @property
    def responseHeaders(self) -> RawHeaders: ...

    def getHeader(self, key: str) -> str | None: ...

    def getClientIP(self) -> str | None: ...

    def setResponseCode(self, code: int, message: bytes | None = None) -> None: ...

    def setHeader(self, name: bytes | str, value: bytes | str) -> None: ...

    def write(self, data: bytes) -> None: ...

    def finish(self) -> None: ...

    def registerProducer(self, producer: PullProducer, streaming: bool) -> None: ...

    def unregisterProducer(self) -> None: ...


class PullProducer(Protocol):
    def resumeProducing(self) -> None: ...

    def pauseProducing(self) -> None: ...

    def stopProducing(self) -> None: ...


class BodyConsumer(Protocol):
    """Byte sink used by ``BytesBodyProducer``."""

    def write(self, data: bytes) -> object: ...


class AgentHeaders(Protocol):
    """Header bag on an Agent response."""

    def getAllRawHeaders(self) -> Iterator[tuple[bytes, Sequence[bytes]]]: ...


class AgentResponse(Protocol):
    """Fields read from Twisted ``IResponse`` after ``Agent.request``."""

    code: int
    phrase: bytes
    headers: AgentHeaders

    def deliverBody(self, protocol: object, /) -> None: ...


class ReactorRunner(Protocol):
    """Minimal reactor surface used to start the event loop."""

    def run(self) -> object: ...
