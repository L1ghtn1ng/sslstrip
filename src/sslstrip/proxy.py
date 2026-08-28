"""Twisted HTTPChannel adapter that bridges to native async request handling."""

import logging
from typing import override

from twisted.internet.defer import Deferred
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.interfaces import IReactorTCP, IReactorTime
from twisted.python.failure import Failure
from twisted.web import http

from sslstrip import __version__
from sslstrip.app import App
from sslstrip.config import AppConfig, ConfigError
from sslstrip.cookies import SessionExpirer
from sslstrip.links import SecureLinkStore
from sslstrip.logs import TrafficLog
from sslstrip.request_handler import handle_request
from sslstrip.twisted_types import ReactorRunner
from sslstrip.upstream import UpstreamResponse, build_agent, request_upstream

logger = logging.getLogger('sslstrip')


class StrippingRequest(http.Request):
    """Twisted Request whose ``process`` callback schedules async handling."""

    @override
    def getHeader(self, key: str) -> str | None:
        raw = super().getHeader(key)
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw.decode('latin-1')
        return raw

    @override
    def process(self) -> None:
        channel = self.channel
        factory = channel.factory if channel is not None else None
        if not isinstance(factory, StrippingFactory):
            self.setResponseCode(500)
            self.finish()
            return
        deferred = Deferred.fromCoroutine(handle_request(self, factory.app))
        deferred.addErrback(_log_handler_failure, self)


class StrippingChannel(http.HTTPChannel):
    """HTTP/1.1 channel that builds :class:`StrippingRequest` instances."""

    requestFactory = StrippingRequest


class StrippingFactory(http.HTTPFactory):
    """HTTP factory that owns the :class:`App` for this process."""

    protocol = StrippingChannel

    def __init__(self, app: App) -> None:
        super().__init__()
        self.app = app


def build_app(config: AppConfig, reactor: IReactorTime) -> App:
    """Construct process-owned state, including the shared Agent."""
    traffic = TrafficLog(config.traffic_log_mode, config.traffic_log_file)
    agent, _pool = build_agent(reactor, connect_timeout=config.connect_timeout, ca_file=config.ca_file)

    async def fetch(
        *,
        method: bytes,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        timeout: float,
        max_body_size: int,
    ) -> UpstreamResponse:
        return await request_upstream(
            agent,
            reactor,
            method=method,
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
            max_body_size=max_body_size,
        )

    return App(
        config=config,
        links=SecureLinkStore(config.link_ttl_seconds, config.link_limit),
        sessions=SessionExpirer(enabled=config.kill_sessions),
        traffic=traffic,
        fetch=fetch,
    )


def start_proxy(reactor: IReactorTCP, config: AppConfig) -> App:
    """Bind the stripping proxy on ``config.listen_host:listen_port``.

    ``TCP4ServerEndpoint.listen`` resolves synchronously, so a bind failure
    is reported here instead of surfacing as an unhandled Deferred later.
    """
    app = build_app(config, reactor)
    factory = StrippingFactory(app)
    endpoint = TCP4ServerEndpoint(reactor, config.listen_port, interface=config.listen_host)
    failures: list[Failure] = []
    endpoint.listen(factory).addErrback(failures.append)
    if failures:
        detail = failures[0].getErrorMessage()
        raise ConfigError(f'cannot listen on {config.listen_host}:{config.listen_port}: {detail}')
    logger.info('sslstrip %s listening on %s:%s', __version__, config.listen_host, config.listen_port)
    print(f'sslstrip {__version__} listening on {config.listen_host}:{config.listen_port}', flush=True)
    return app


def run_reactor(reactor: ReactorRunner) -> None:
    """Start the Twisted reactor."""
    reactor.run()


def _log_handler_failure(failure: Failure, request: StrippingRequest) -> None:
    logger.error('Request handler failed: %s', failure.getErrorMessage())
    try:
        if not request.finished:
            request.setResponseCode(502)
            request.finish()
    except Exception:
        logger.debug('Could not finish failed request', exc_info=True)
