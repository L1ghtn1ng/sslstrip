"""nftables JSON construction and ownership markers."""

import json
from ipaddress import IPv4Address
from types import SimpleNamespace

import pytest

from sslstrip.nftables import (
    NftablesError,
    RedirectSpec,
    apply_json,
    create_table_payload,
    delete_table_payload,
    list_table,
    owner_comment,
    parse_owner_comment,
    table_owner,
)


def test_create_payload_scopes_rule() -> None:
    spec = RedirectSpec(interface='dummy0', target=IPv4Address('10.66.0.2'), proxy_port=10000, owner='abc-uuid')
    payload = json.loads(create_table_payload(spec).decode('utf-8'))
    items = payload['nftables']
    table = items[0]['create']['table']
    assert table['family'] == 'ip'
    assert table['name'] == 'sslstrip'
    assert table['comment'] == 'sslstrip-owner=abc-uuid'
    rule = items[2]['add']['rule']
    expr = rule['expr']
    assert expr[0]['match']['right'] == 'dummy0'
    assert expr[1]['match']['right'] == '10.66.0.2'
    assert expr[2]['match']['right'] == 80
    assert expr[3]['redirect']['port'] == 10000


def test_delete_payload() -> None:
    payload = json.loads(delete_table_payload().decode('utf-8'))
    assert payload['nftables'][0]['delete']['table']['name'] == 'sslstrip'


def test_owner_comment_round_trip() -> None:
    comment = owner_comment('tok')
    assert parse_owner_comment(comment) == 'tok'
    assert parse_owner_comment('other') is None


def test_table_owner_from_listing() -> None:
    listing: dict[str, object] = {
        'nftables': [
            {'table': {'family': 'ip', 'name': 'sslstrip', 'comment': 'sslstrip-owner=xyz'}},
        ]
    }
    assert table_owner(listing) == 'xyz'


def test_table_owner_from_rule_and_empty() -> None:
    listing: dict[str, object] = {
        'nftables': [
            'skip',
            {'rule': {'comment': 'sslstrip-owner=from-rule'}},
        ]
    }
    assert table_owner(listing) == 'from-rule'
    assert table_owner({'nftables': 'nope'}) is None
    assert table_owner({'nftables': [{'table': {'comment': 1}}]}) is None
    assert parse_owner_comment(None) is None
    assert parse_owner_comment('sslstrip-owner=') is None


def test_table_owner_rejects_conflicting_markers() -> None:
    listing: dict[str, object] = {
        'nftables': [
            {'table': {'comment': 'sslstrip-owner=ours'}},
            {'rule': {'comment': 'sslstrip-owner=foreign'}},
        ]
    }
    with pytest.raises(NftablesError, match='conflicting'):
        table_owner(listing)


def test_table_owner_rejects_invalid_marker() -> None:
    listing: dict[str, object] = {
        'nftables': [
            {'table': {'comment': 'sslstrip-owner=ours'}},
            {'rule': {'comment': 'sslstrip-owner='}},
        ]
    }
    with pytest.raises(NftablesError, match='invalid'):
        table_owner(listing)


def test_apply_json_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        'sslstrip.nftables.run_nft',
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stderr=b''),
    )
    apply_json('nft', b'{}')


def test_apply_json_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        'sslstrip.nftables.run_nft',
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stderr=b'boom'),
    )
    with pytest.raises(NftablesError, match='boom'):
        apply_json('nft', b'{}')


def test_list_table_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter(
        [
            SimpleNamespace(returncode=1, stdout=b'', stderr=b'No such file or directory'),
            SimpleNamespace(returncode=0, stdout=b'{"nftables": []}', stderr=b''),
        ]
    )
    monkeypatch.setattr('sslstrip.nftables.run_nft', lambda *_args, **_kwargs: next(results))
    assert list_table('nft') is None


def test_list_table_query_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter(
        [
            SimpleNamespace(returncode=1, stdout=b'', stderr=b'Operation not permitted'),
            SimpleNamespace(returncode=1, stdout=b'', stderr=b'Operation not permitted'),
        ]
    )
    monkeypatch.setattr('sslstrip.nftables.run_nft', lambda *_args, **_kwargs: next(results))
    with pytest.raises(NftablesError, match='Operation not permitted'):
        list_table('nft')


def test_list_table_specific_query_failure_for_existing_table(monkeypatch: pytest.MonkeyPatch) -> None:
    tables = b'{"nftables": [{"table": {"family": "ip", "name": "sslstrip"}}]}'
    results = iter(
        [
            SimpleNamespace(returncode=1, stdout=b'', stderr=b'backend failure'),
            SimpleNamespace(returncode=0, stdout=tables, stderr=b''),
        ]
    )
    monkeypatch.setattr('sslstrip.nftables.run_nft', lambda *_args, **_kwargs: next(results))
    with pytest.raises(NftablesError, match='backend failure'):
        list_table('nft')


def test_list_table_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        'sslstrip.nftables.run_nft',
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b'not-json', stderr=b''),
    )
    with pytest.raises(NftablesError, match='not JSON'):
        list_table('nft')


def test_list_table_not_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        'sslstrip.nftables.run_nft',
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b'[]', stderr=b''),
    )
    with pytest.raises(NftablesError, match='not an object'):
        list_table('nft')


def test_list_table_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        'sslstrip.nftables.run_nft',
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=b'{"nftables": []}', stderr=b''),
    )
    listing = list_table('nft')
    assert listing == {'nftables': []}
