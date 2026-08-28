"""Status mapping for upstream failures and timeouts."""

from sslstrip.errors import ProxyTimeoutError, map_upstream_failure


def test_timeout_maps_to_504() -> None:
    assert map_upstream_failure(ProxyTimeoutError('x')) == 504
    assert map_upstream_failure(TimeoutError('timed out')) == 504


def test_other_failures_map_to_502() -> None:
    assert map_upstream_failure(ConnectionRefusedError('no')) == 502
    assert map_upstream_failure(OSError('dns')) == 502


def test_timeout_by_name_and_message() -> None:
    class ConnectingCancelledError(Exception):
        pass

    assert map_upstream_failure(ConnectingCancelledError('x')) == 504
    assert map_upstream_failure(RuntimeError('connection timed out')) == 504


def test_timeout_via_cause() -> None:
    try:
        raise ProxyTimeoutError('inner')
    except ProxyTimeoutError as inner:
        wrapped = RuntimeError('outer')
        wrapped.__cause__ = inner
        assert map_upstream_failure(wrapped) == 504


def test_timeout_via_context() -> None:
    wrapped = RuntimeError('outer')
    wrapped.__cause__ = None
    wrapped.__context__ = TimeoutError('ctx')
    assert map_upstream_failure(wrapped) == 504
