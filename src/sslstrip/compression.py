"""Decode and re-encode gzip, Brotli, and Zstandard response bodies."""

import gzip
import logging
from compression.zstd import ZstdDecompressor, ZstdError
from compression.zstd import compress as zstd_compress
from dataclasses import dataclass
from io import BytesIO

import brotli

logger = logging.getLogger('sslstrip')

KNOWN_ENCODINGS = frozenset({'gzip', 'x-gzip', 'br', 'zstd', 'identity'})


class DecodeError(Exception):
    """The body could not be decoded as the declared encoding stack."""


class OversizedError(Exception):
    """Decoded output would exceed the configured size limit."""


@dataclass(frozen=True, slots=True)
class DecodeResult:
    """Outcome of attempting to decode a ``Content-Encoding`` stack."""

    data: bytes
    encodings: tuple[str, ...]
    decoded: bool
    passthrough_reason: str | None


def parse_encodings(header: str | None) -> list[str]:
    """Split a Content-Encoding header into normalized tokens."""
    if header is None or header.strip() == '':
        return []
    return [token.strip().lower() for token in header.split(',') if token.strip()]


def decode_body(data: bytes, encodings: list[str], max_size: int) -> DecodeResult:
    """Decode stacked encodings, or pass the original bytes through.

    Unknown, malformed, or oversized payloads are returned unchanged with
    ``decoded=False`` so the proxy can forward them byte-for-byte.
    """
    if not encodings or encodings == ['identity']:
        if len(data) > max_size:
            logger.warning('Decoded body exceeds %s bytes; passing through unchanged', max_size)
            return DecodeResult(data, tuple(encodings), decoded=False, passthrough_reason='oversized')
        return DecodeResult(data, tuple(encodings), decoded=True, passthrough_reason=None)
    unknown = [item for item in encodings if item not in KNOWN_ENCODINGS]
    if unknown:
        logger.warning('Unknown Content-Encoding %s; passing through unchanged', ', '.join(unknown))
        return DecodeResult(data, tuple(encodings), decoded=False, passthrough_reason='unknown-encoding')
    current = data
    try:
        for encoding in reversed(encodings):
            if encoding == 'identity':
                continue
            current = _decode_one(current, encoding, max_size)
            if len(current) > max_size:
                raise OversizedError
    except OversizedError:
        logger.warning('Decoded body exceeds %s bytes; passing through unchanged', max_size)
        return DecodeResult(data, tuple(encodings), decoded=False, passthrough_reason='oversized')
    except DecodeError, OSError, ValueError, brotli.error:
        logger.warning('Malformed %s body; passing through unchanged', ', '.join(encodings))
        return DecodeResult(data, tuple(encodings), decoded=False, passthrough_reason='malformed')
    return DecodeResult(current, tuple(encodings), decoded=True, passthrough_reason=None)


def encode_body(data: bytes, encodings: list[str]) -> bytes:
    """Re-apply a supported encoding stack in the original order."""
    current = data
    for encoding in encodings:
        if encoding in {'identity', ''}:
            continue
        current = _encode_one(current, encoding)
    return current


def _decode_one(data: bytes, encoding: str, max_size: int) -> bytes:
    if encoding in {'gzip', 'x-gzip'}:
        return _decode_gzip(data, max_size)
    if encoding == 'br':
        return _decode_brotli(data, max_size)
    if encoding == 'zstd':
        return _decode_zstd(data, max_size)
    raise DecodeError(f'unsupported encoding {encoding}')


def _encode_one(data: bytes, encoding: str) -> bytes:
    if encoding in {'gzip', 'x-gzip'}:
        return gzip.compress(data)
    if encoding == 'br':
        return bytes(brotli.compress(data))
    if encoding == 'zstd':
        return zstd_compress(data)
    raise DecodeError(f'unsupported encoding {encoding}')


def _decode_gzip(data: bytes, max_size: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=BytesIO(data), mode='rb') as handle:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    raise OversizedError
                chunks.append(chunk)
    except OversizedError:
        raise
    except (OSError, EOFError) as exc:
        raise DecodeError('malformed gzip') from exc
    return b''.join(chunks)


def _decode_brotli(data: bytes, max_size: int) -> bytes:
    decompressor = brotli.Decompressor()
    try:
        output = decompressor.process(data, output_buffer_limit=max_size + 1)
    except TypeError:
        output = decompressor.process(data)
    except brotli.error as exc:
        raise DecodeError('malformed brotli') from exc
    if len(output) > max_size:
        raise OversizedError
    if not decompressor.is_finished():
        if len(output) >= max_size:
            raise OversizedError
        raise DecodeError('truncated brotli')
    return bytes(output)


def _decode_zstd(data: bytes, max_size: int) -> bytes:
    decompressor = ZstdDecompressor()
    try:
        output = decompressor.decompress(data, max_size + 1)
    except ZstdError as exc:
        raise DecodeError('malformed zstd') from exc
    if len(output) > max_size or not decompressor.eof:
        if len(output) > max_size or not decompressor.needs_input:
            raise OversizedError
        raise DecodeError('truncated zstd')
    return output
