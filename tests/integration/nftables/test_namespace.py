"""Privileged nftables tests inside an isolated network namespace."""

import os
import shutil
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.nftables


def test_managed_nftables_lifecycle() -> None:
    if os.geteuid() != 0:
        pytest.skip('nftables namespace tests require root')
    if shutil.which('nft') is None or shutil.which('ip') is None or shutil.which('unshare') is None:
        pytest.skip('nft/ip/unshare not available')
    uid = os.environ.get('SUDO_UID', '0')
    gid = os.environ.get('SUDO_GID', '0')
    python = sys.executable
    inner = textwrap.dedent(
        f"""
        set -euo pipefail
        ip link add dummy0 type dummy
        ip addr add 10.66.0.1/24 dev dummy0
        ip link set dummy0 up
        echo 0 > /proc/sys/net/ipv4/ip_forward
        {python} -m sslstrip run --manage-network --interface dummy0 --target 10.66.0.2 --listen-port 18080 --run-as {uid}:{gid} --listen-host 10.66.0.1 &
        PID=$!
        for i in $(seq 1 50); do
          if nft list table ip sslstrip >/dev/null 2>&1; then
            break
          fi
          sleep 0.1
        done
        nft list table ip sslstrip
        nft -j list table ip sslstrip | grep 10.66.0.2
        nft -j list table ip sslstrip | grep dummy0
        grep -q 1 /proc/sys/net/ipv4/ip_forward
        kill -TERM "$PID"
        wait "$PID" || true
        if nft list table ip sslstrip >/dev/null 2>&1; then
          echo "table still present after SIGTERM" >&2
          exit 1
        fi
        grep -q 0 /proc/sys/net/ipv4/ip_forward
        """
    )
    completed = subprocess.run(
        ['unshare', '--net', 'bash', '-c', inner],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
