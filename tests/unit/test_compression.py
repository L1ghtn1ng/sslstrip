"""gzip, Brotli, zstd, stacked encodings, and passthrough tests."""

import gzip
from compression.zstd import compress as zstd_compress

import brotli
import pytest

from sslstrip.compression import decode_body, encode_body, parse_encodings


def test_parse_encodings() -> None:
    assert parse_encodings('gzip, br') == ['gzip', 'br']
    assert parse_encodings(None) == []


def test_gzip_round_trip() -> None:
    original = b'hello https://example.com/'
    encoded = gzip.compress(original)
    result = decode_body(encoded, ['gzip'], max_size=1024)
    assert result.decoded
    assert result.data == original
    assert encode_body(original, ['gzip']) != original


def test_brotli_round_trip() -> None:
    original = b'brotli payload'
    encoded = bytes(brotli.compress(original))
    result = decode_body(encoded, ['br'], max_size=1024)
    assert result.decoded
    assert result.data == original


def test_zstd_round_trip() -> None:
    original = b'zstd payload'
    encoded = zstd_compress(original)
    result = decode_body(encoded, ['zstd'], max_size=1024)
    assert result.decoded
    assert result.data == original


def test_stacked_gzip_then_br() -> None:
    original = b'stacked encodings'
    encoded = bytes(brotli.compress(gzip.compress(original)))
    result = decode_body(encoded, ['gzip', 'br'], max_size=1024)
    assert result.decoded
    assert result.data == original


def test_unknown_encoding_passthrough() -> None:
    original = b'not-really-compressed'
    result = decode_body(original, ['deflate'], max_size=1024)
    assert not result.decoded
    assert result.data is original
    assert result.passthrough_reason == 'unknown-encoding'


def test_malformed_gzip_passthrough() -> None:
    original = b'not gzip'
    result = decode_body(original, ['gzip'], max_size=1024)
    assert not result.decoded
    assert result.data is original
    assert result.passthrough_reason == 'malformed'


def test_oversized_decoded_passthrough() -> None:
    original = b'x' * 200
    encoded = gzip.compress(original)
    result = decode_body(encoded, ['gzip'], max_size=50)
    assert not result.decoded
    assert result.data is encoded
    assert result.passthrough_reason == 'oversized'


def test_identity_under_limit() -> None:
    data = b'short'
    result = decode_body(data, [], max_size=100)
    assert result.decoded
    assert result.data == data


def test_identity_oversized_passthrough() -> None:
    data = b'x' * 200
    result = decode_body(data, [], max_size=50)
    assert not result.decoded
    assert result.passthrough_reason == 'oversized'


def test_identity_token_round_trip() -> None:
    data = b'hello'
    result = decode_body(data, ['identity'], max_size=100)
    assert result.decoded
    assert encode_body(data, ['identity']) == data


def test_x_gzip_alias() -> None:
    original = b'alias'
    result = decode_body(gzip.compress(original), ['x-gzip'], max_size=1024)
    assert result.decoded
    assert result.data == original
    assert encode_body(original, ['x-gzip']) != original


def test_truncated_brotli_passthrough() -> None:
    encoded = bytes(brotli.compress(b'hello-brotli'))
    result = decode_body(encoded[:-4], ['br'], max_size=1024)
    assert not result.decoded
    assert result.passthrough_reason in {'malformed'}


def test_truncated_zstd_passthrough() -> None:
    encoded = zstd_compress(b'hello-zstd-payload')
    result = decode_body(encoded[:4], ['zstd'], max_size=1024)
    assert not result.decoded


def test_truncated_gzip_passthrough() -> None:
    original = gzip.compress(b'hello gzip payload')[:-8]
    result = decode_body(original, ['gzip'], max_size=1024)
    assert not result.decoded
    assert result.data is original
    assert result.passthrough_reason == 'malformed'


def test_malformed_zstd_passthrough() -> None:
    original = b'bad-magic-zstd'
    result = decode_body(original, ['zstd'], max_size=1024)
    assert not result.decoded
    assert result.data is original
    assert result.passthrough_reason == 'malformed'


def test_encode_unsupported() -> None:
    from sslstrip.compression import DecodeError, _encode_one

    with pytest.raises(DecodeError):
        _encode_one(b'x', 'deflate')
