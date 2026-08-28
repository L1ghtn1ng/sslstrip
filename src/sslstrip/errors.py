"""Client and upstream error mapping for the stripping proxy."""


class ProxyClientError(Exception):
    """An error that should be returned to the downstream client."""

    def __init__(self, code: int, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class ProxyTimeoutError(Exception):
    """The upstream connect or response window expired."""


def map_upstream_failure(exc: BaseException) -> int:
    """Map an upstream exception to 502 (Bad Gateway) or 504 (Gateway Timeout)."""
    if _is_timeout(exc):
        return 504
    return 502


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, (ProxyTimeoutError, TimeoutError)):
        return True
    name = type(exc).__name__
    if name in {'TimeoutError', 'ConnectingCancelledError', 'CancelledError'}:
        return True
    message = str(exc).lower()
    if 'timeout' in message or 'timed out' in message:
        return True
    cause = exc.__cause__
    if cause is not None and cause is not exc:
        return _is_timeout(cause)
    context = exc.__context__
    if context is not None and context is not exc:
        return _is_timeout(context)
    return False
