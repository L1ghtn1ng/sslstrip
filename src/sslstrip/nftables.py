"""Construct nftables JSON and invoke ``nft`` without a shell."""

import json
import logging
import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Final

logger = logging.getLogger('sslstrip')

TABLE_NAME: Final = 'sslstrip'
TABLE_FAMILY: Final = 'ip'
OWNER_PREFIX: Final = 'sslstrip-owner='


class NftablesError(RuntimeError):
    """An nftables operation failed or returned unexpected state."""


@dataclass(frozen=True, slots=True)
class RedirectSpec:
    """Parameters for the managed NAT redirect rule."""

    interface: str
    target: IPv4Address
    proxy_port: int
    owner: str


def owner_comment(owner: str) -> str:
    """Return the ownership marker stored on the dedicated table and rule."""
    return f'{OWNER_PREFIX}{owner}'


def parse_owner_comment(comment: str | None) -> str | None:
    """Extract the ownership UUID from an nftables comment."""
    if comment is None or not comment.startswith(OWNER_PREFIX):
        return None
    token = comment[len(OWNER_PREFIX) :].strip()
    return token or None


def create_table_payload(spec: RedirectSpec) -> bytes:
    """JSON document that atomically creates the dedicated NAT table."""
    comment = owner_comment(spec.owner)
    document = {
        'nftables': [
            {
                'create': {
                    'table': {
                        'family': TABLE_FAMILY,
                        'name': TABLE_NAME,
                        'comment': comment,
                    }
                }
            },
            {
                'add': {
                    'chain': {
                        'family': TABLE_FAMILY,
                        'table': TABLE_NAME,
                        'name': 'prerouting',
                        'type': 'nat',
                        'hook': 'prerouting',
                        'prio': -100,
                    }
                }
            },
            {
                'add': {
                    'rule': {
                        'family': TABLE_FAMILY,
                        'table': TABLE_NAME,
                        'chain': 'prerouting',
                        'comment': comment,
                        'expr': [
                            {
                                'match': {
                                    'op': '==',
                                    'left': {'meta': {'key': 'iifname'}},
                                    'right': spec.interface,
                                }
                            },
                            {
                                'match': {
                                    'op': '==',
                                    'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                                    'right': str(spec.target),
                                }
                            },
                            {
                                'match': {
                                    'op': '==',
                                    'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}},
                                    'right': 80,
                                }
                            },
                            {'redirect': {'port': spec.proxy_port}},
                        ],
                    }
                }
            },
        ]
    }
    return json.dumps(document).encode('utf-8')


def delete_table_payload() -> bytes:
    """JSON document that deletes the dedicated table."""
    document = {
        'nftables': [
            {
                'delete': {
                    'table': {
                        'family': TABLE_FAMILY,
                        'name': TABLE_NAME,
                    }
                }
            }
        ]
    }
    return json.dumps(document).encode('utf-8')


def run_nft(executable: str, args: list[str], stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run ``nft`` with an explicit argument vector and no shell."""
    command = [executable, *args]
    logger.debug('nftables command: %s', command)
    return subprocess.run(command, input=stdin, capture_output=True, check=False, shell=False)


def apply_json(executable: str, payload: bytes) -> None:
    """Feed a JSON document to ``nft -j -f -`` and raise on failure."""
    result = run_nft(executable, ['-j', '-f', '-'], stdin=payload)
    if result.returncode != 0:
        stderr = result.stderr.decode('utf-8', errors='replace')
        raise NftablesError(f'nftables update failed: {stderr.strip()}')


def list_table(executable: str) -> dict[str, object] | None:
    """Return the JSON listing of the dedicated table, or None if missing."""
    result = run_nft(executable, ['-j', 'list', 'table', TABLE_FAMILY, TABLE_NAME])
    if result.returncode != 0:
        tables = run_nft(executable, ['-j', 'list', 'tables'])
        if tables.returncode != 0:
            detail = _stderr_detail(result) or _stderr_detail(tables)
            raise NftablesError(f'nftables table query failed: {detail}')
        listing = _load_listing(tables.stdout)
        if not _contains_table(listing):
            return None
        detail = _stderr_detail(result)
        raise NftablesError(f'nftables table query failed: {detail}')
    return _load_listing(result.stdout)


def _load_listing(output: bytes) -> dict[str, object]:
    try:
        loaded = json.loads(output.decode('utf-8'))
    except json.JSONDecodeError as exc:
        raise NftablesError('nftables list output is not JSON') from exc
    if not isinstance(loaded, dict):
        raise NftablesError('nftables list output is not an object')
    typed: dict[str, object] = {}
    for key, value in loaded.items():
        typed[str(key)] = value
    return typed


def _contains_table(listing: dict[str, object]) -> bool:
    items = listing.get('nftables')
    if not isinstance(items, list):
        raise NftablesError('nftables list output has no nftables array')
    for item in items:
        if not isinstance(item, dict):
            continue
        table = item.get('table')
        if not isinstance(table, dict):
            continue
        if table.get('family') == TABLE_FAMILY and table.get('name') == TABLE_NAME:
            return True
    return False


def _stderr_detail(result: subprocess.CompletedProcess[bytes]) -> str:
    return result.stderr.decode('utf-8', errors='replace').strip() or f'exit status {result.returncode}'


def table_owner(listing: dict[str, object]) -> str | None:
    """Read the ownership UUID from a ``nft -j list`` document."""
    items = listing.get('nftables')
    if not isinstance(items, list):
        return None
    owners: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        table = item.get('table')
        if isinstance(table, dict):
            comment = table.get('comment')
            if isinstance(comment, str):
                owner = parse_owner_comment(comment)
                if comment.startswith(OWNER_PREFIX) and owner is None:
                    raise NftablesError('invalid sslstrip ownership marker')
                if owner is not None:
                    owners.add(owner)
        rule = item.get('rule')
        if isinstance(rule, dict):
            comment = rule.get('comment')
            if isinstance(comment, str):
                owner = parse_owner_comment(comment)
                if comment.startswith(OWNER_PREFIX) and owner is None:
                    raise NftablesError('invalid sslstrip ownership marker')
                if owner is not None:
                    owners.add(owner)
    if len(owners) > 1:
        raise NftablesError(f'conflicting sslstrip ownership markers: {", ".join(sorted(owners))}')
    return next(iter(owners), None)
