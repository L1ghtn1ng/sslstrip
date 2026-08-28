# sslstrip 5.0

sslstrip is a Linux proxy that implements Moxie Marlinspike's HTTPS stripping attacks for **authorized testing only**. Use it only on systems and networks you own or have explicit permission to test.

Ported from Python 2 to 3 by Jay Townsend, then rewritten for Python 3.14 as a typed, asynchronous Twisted application.

[![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1

## Requirements

Python 3.14+ and [uv](https://docs.astral.sh/uv/getting-started/installation/). Transparent interception additionally needs Linux, root privileges, `nft`, `ip`, and a separate way to route the authorized lab target through this host.

```bash
uv sync --group dev
uv run sslstrip --version
```

Install from a wheel:

```bash
uv build
uv tool install dist/sslstrip-5.0.0-*.whl
sslstrip --version
```

## Quick start

For a local explicit-proxy check, start sslstrip on its safe loopback default:

```bash
uv run sslstrip run --listen-port 10000 -v
```

In another terminal, request an HTTP lab origin through it:

```bash
curl --proxy http://127.0.0.1:10000 http://lab.example.test/
```

The origin page must be available over HTTP and contain an HTTPS link for sslstrip to rewrite. Use a lab hostname that is not HSTS-preloaded. Stop the proxy with `Ctrl-C`.

## Limitations

sslstrip does **not** defeat browser HSTS preload lists or Content-Security-Policy `upgrade-insecure-requests`. Modern browsers will not send plaintext HTTP to preload-listed hosts. This tool is for lab origins that still speak HTTP and optional HTTPS, not for attacking current mainstream websites.

ARP/NDP spoofing is **not** included. Redirect traffic onto this host with your own lab tooling (`arpspoof`, etc.).

## Manual mode

Manual mode leaves forwarding, traffic redirection, and cleanup to you. The loopback default is suitable for the explicit-proxy example above, but it cannot receive packets redirected in `PREROUTING` from another machine. For transparent interception, bind sslstrip to the IPv4 address of the ingress interface.

First identify the address:

```bash
ip -4 address show dev eth0
```

If the lab-facing address is `192.0.2.1`, start the proxy in one terminal:

```bash
uv run sslstrip run --listen-host 192.0.2.1 --listen-port 10000 -v
```

In another terminal, save the current forwarding value, enable forwarding, and redirect only the authorized target:

```bash
previous_forwarding=$(sudo sysctl -n net.ipv4.ip_forward)
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft add table ip lab
sudo nft add chain ip lab prerouting '{ type nat hook prerouting priority dstnat; }'
sudo nft add rule ip lab prerouting iifname eth0 ip saddr 192.0.2.10 tcp dport 80 redirect to :10000
```

Route `192.0.2.10` through this host using your authorized lab tooling. When finished, remove the manual table and restore the forwarding value saved earlier:

```bash
sudo nft delete table ip lab
sudo sysctl -w "net.ipv4.ip_forward=${previous_forwarding}"
```

Substitute the real interface, interface address, target address, and previous forwarding value. Do not bind to `0.0.0.0` unless exposure on every interface is intentional.

## Managed mode

Managed mode performs the forwarding, target-scoped redirect, privilege drop, and cleanup steps. A small root supervisor takes an exclusive `/run/sslstrip` lock, durably records recovery state, enables IPv4 forwarding only if needed, installs a dedicated nftables IPv4 NAT table scoped to one interface and one source IPv4 address on TCP/80, then runs the Twisted worker as `SUDO_UID`/`SUDO_GID`. Direct root invocation requires `--run-as`.

Run the environment checks, then start managed mode:

```bash
sudo uv run sslstrip doctor --interface eth0 --target 192.0.2.10 --listen-port 10000
sudo uv run sslstrip run --manage-network --interface eth0 --target 192.0.2.10 --listen-port 10000
```

On SIGTERM the supervisor deletes **only** its owned table and restores the previous forwarding value.

If the process is killed ungracefully, recover before attempting another managed run:

```bash
sudo uv run sslstrip cleanup
```

Cleanup verifies the stored ownership identifier against the nftables marker, stops the exact recorded worker when it is still running, refuses foreign or ambiguous state, and never signals a reused PID.

The default state directory is `/run/sslstrip`. A custom `--state-dir` and its existing non-system ancestors must be root-owned and must not be group- or world-writable; the final directory must use mode `0700`. Standard sticky temporary directories such as `/tmp` are accepted, though `/run/sslstrip` is preferred. The supervisor creates missing components without following symlinks. State and lock files use mode `0600`, and managed startup refuses to overwrite stale recovery state.

## Private lab CA

TLS is always verified against the system trust store. There is no insecure-TLS switch. For origins signed by a private lab CA:

```bash
uv run sslstrip run --ca-file /path/to/lab-ca.pem
```

## Traffic logs

Operational logs go to stderr (`-v` / `-vv`). Unredacted request/response bodies require **both** flags:

```bash
uv run sslstrip run --traffic-log all --traffic-log-file /tmp/sslstrip-traffic.log
```

`--traffic-log` is one of `post`, `secure`, or `all`. The file must be a regular non-symlink path and is created or forced to mode `0600`. The file will contain credentials and cookie values.

## Doctor

Read-only checks for Python, dependencies, interface, nftables, privilege, port, target, state directory, and certificate file:

```bash
sudo uv run sslstrip doctor --interface eth0 --target 192.0.2.10
```

## Development checks

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run ty check
uv run pytest --cov=sslstrip --cov-report=term-missing
```

## License

GNU GPL v3. See `COPYING`.
