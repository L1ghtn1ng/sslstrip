"""Unit tests for the Twisted proxy adapter helpers."""

from typing import cast

import pytest
from tests.fakes import sample_config
from twisted.internet.error import CannotListenError
from twisted.internet.interfaces import IReactorTCP
from twisted.python.failure import Failure

from sslstrip.config import ConfigError
from sslstrip.proxy import StrippingRequest, _log_handler_failure, run_reactor, start_proxy


def test_run_reactor_invokes_run() -> None:
    called: list[bool] = []

    class Reactor:
        def run(self) -> None:
            called.append(True)

    run_reactor(Reactor())
    assert called == [True]


def test_start_proxy_bind_failure_is_config_error() -> None:
    class Reactor:
        def listenTCP(self, port: int, factory: object, backlog: int = 50, interface: str = '') -> object:
            del factory, backlog, interface
            raise CannotListenError('', port, OSError(98, 'Address already in use'))

    config = sample_config(listen_port=10000)
    with pytest.raises(ConfigError, match='cannot listen'):
        start_proxy(cast('IReactorTCP', Reactor()), config)


def test_log_handler_failure_finishes_request() -> None:
    class Dummy:
        finished = False
        code = 0

        def setResponseCode(self, code: int, message: bytes | None = None) -> None:
            del message
            self.code = code

        def finish(self) -> None:
            self.finished = True

    dummy = Dummy()
    _log_handler_failure(Failure(RuntimeError('boom')), cast('StrippingRequest', dummy))
    assert dummy.code == 502
    assert dummy.finished


def test_log_handler_failure_already_finished() -> None:
    class Dummy:
        finished = True

        def setResponseCode(self, code: int, message: bytes | None = None) -> None:
            raise AssertionError('should not be called')

        def finish(self) -> None:
            raise AssertionError('should not be called')

    _log_handler_failure(Failure(RuntimeError('boom')), cast('StrippingRequest', Dummy()))


def test_log_handler_failure_swallows_finish_error() -> None:
    class Dummy:
        finished = False

        def setResponseCode(self, code: int, message: bytes | None = None) -> None:
            raise RuntimeError('cannot finish')

        def finish(self) -> None:
            return None

    _log_handler_failure(Failure(RuntimeError('boom')), cast('StrippingRequest', Dummy()))
