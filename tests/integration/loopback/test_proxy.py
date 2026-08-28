"""Subprocess loopback tests against real Twisted sockets."""

import http.client
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, override

from tests.certs import write_lab_ca_and_leaf


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return int(port)


def _wait_port(port: int, timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.connect(('127.0.0.1', port))
            probe.close()
            return
        except OSError:
            time.sleep(0.05)
        finally:
            probe.close()
    raise AssertionError(f'port {port} did not open')


class _Origin(BaseHTTPRequestHandler):
    body: ClassVar[bytes] = b'<html>hello</html>'
    content_type: ClassVar[str] = 'text/html'
    last_method: ClassVar[str] = ''
    last_body: ClassVar[bytes] = b''

    @override
    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:
        self._respond(self.body)

    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', '0'))
        type(self).last_body = self.rfile.read(length)
        type(self).last_method = 'POST'
        self._respond(b'posted')

    def do_PUT(self) -> None:
        length = int(self.headers.get('Content-Length', '0'))
        type(self).last_body = self.rfile.read(length)
        type(self).last_method = 'PUT'
        self._respond(b'put-ok')

    def _respond(self, payload: bytes) -> None:
        type(self).last_method = self.command
        self.send_response(200)
        self.send_header('Content-Type', self.content_type)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _serve(
    handler: type[BaseHTTPRequestHandler], *, tls: tuple[Path, Path] | None = None
) -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    if tls is not None:
        cert, key = tls
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def _start_sslstrip(port: int, extra: list[str] | None = None) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        '-m',
        'sslstrip',
        'run',
        '--listen-host',
        '127.0.0.1',
        '--listen-port',
        str(port),
        '-v',
    ]
    if extra:
        command.extend(extra)
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        _wait_port(port)
    except AssertionError:
        stdout, stderr = b'', b''
        try:
            stdout, stderr = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=2)
        raise AssertionError(
            f'port {port} did not open (returncode={proc.returncode})\nstdout={stdout!r}\nstderr={stderr!r}'
        ) from None
    return proc


def _proxy_request(
    proxy_port: int, origin_port: int, method: str = 'GET', body: bytes | None = None, path: str = '/'
) -> http.client.HTTPResponse:
    conn = http.client.HTTPConnection('127.0.0.1', proxy_port, timeout=10)
    headers = {'Host': f'127.0.0.1:{origin_port}'}
    conn.request(method, path, body=body, headers=headers)
    return conn.getresponse()


def test_get_and_post_round_trip() -> None:
    class Handler(_Origin):
        body = b'<html>plain</html>'

    server, origin_port, _thread = _serve(Handler)
    proxy_port = _free_port()
    proc = _start_sslstrip(proxy_port)
    try:
        response = _proxy_request(proxy_port, origin_port)
        payload = response.read()
        assert response.status == 200
        assert payload == b'<html>plain</html>'
        posted = _proxy_request(proxy_port, origin_port, method='POST', body=b'a=1')
        assert posted.status == 200
        assert posted.read() == b'posted'
        assert Handler.last_body == b'a=1'
        put = _proxy_request(proxy_port, origin_port, method='PUT', body=b'data')
        assert put.status == 200
        assert Handler.last_method == 'PUT'
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        server.shutdown()


def test_close_delimited_response_body() -> None:
    class Handler(_Origin):
        @override
        def _respond(self, payload: bytes) -> None:
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(payload)
            self.close_connection = True

    server, origin_port, _thread = _serve(Handler)
    proxy_port = _free_port()
    proc = _start_sslstrip(proxy_port)
    try:
        response = _proxy_request(proxy_port, origin_port)
        assert response.status == 200
        assert response.read() == Handler.body
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        server.shutdown()


def test_https_rewrite_and_private_ca(tmp_path: Path) -> None:
    ca, cert, key = write_lab_ca_and_leaf(tmp_path, '127.0.0.1')

    class SecureHandler(_Origin):
        body = b'<html>secure-ok</html>'

    class PublicHandler(_Origin):
        pass

    secure_server, secure_port, _st = _serve(SecureHandler, tls=(cert, key))
    PublicHandler.body = f'<a href="https://127.0.0.1:{secure_port}/s">x</a>'.encode()
    public_server, public_port, _pt = _serve(PublicHandler)
    proxy_port = _free_port()
    proc = _start_sslstrip(proxy_port, extra=['--ca-file', str(ca)])
    try:
        first = _proxy_request(proxy_port, public_port)
        html = first.read()
        assert first.status == 200
        assert b'https://' not in html
        marker = f'http://127.0.0.1:{secure_port}/s'.encode()
        assert marker in html
        second = _proxy_request(proxy_port, secure_port, path='/s')
        assert second.status == 200
        assert second.read() == b'<html>secure-ok</html>'
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        public_server.shutdown()
        secure_server.shutdown()


def test_untrusted_certificate_is_502(tmp_path: Path) -> None:
    _ca, cert, key = write_lab_ca_and_leaf(tmp_path, '127.0.0.1')

    class SecureHandler(_Origin):
        body = b'secret'

    server, origin_port, _thread = _serve(SecureHandler, tls=(cert, key))
    proxy_port = _free_port()
    proc = _start_sslstrip(proxy_port)
    try:

        class PublicHandler(_Origin):
            pass

        PublicHandler.body = f'<a href="https://127.0.0.1:{origin_port}/">x</a>'.encode()
        public, public_port, _pt = _serve(PublicHandler)
        try:
            _proxy_request(proxy_port, public_port).read()
            failed = _proxy_request(proxy_port, origin_port)
            assert failed.status == 502
        finally:
            public.shutdown()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        server.shutdown()


def test_bind_failure_exits_nonzero() -> None:
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.bind(('127.0.0.1', 0))
    blocker.listen(1)
    port = int(blocker.getsockname()[1])
    command = [
        sys.executable,
        '-m',
        'sslstrip',
        'run',
        '--listen-host',
        '127.0.0.1',
        '--listen-port',
        str(port),
    ]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = proc.communicate(timeout=10)
        assert proc.returncode == 2
        assert b'cannot listen' in stderr
        assert b'listening on' not in stdout
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
        blocker.close()


def test_clean_shutdown() -> None:
    class Handler(_Origin):
        body = b'ok'

    server, origin_port, _thread = _serve(Handler)
    proxy_port = _free_port()
    proc = _start_sslstrip(proxy_port)
    try:
        assert _proxy_request(proxy_port, origin_port).status == 200
        proc.terminate()
        assert proc.wait(timeout=5) == 0 or proc.returncode is not None
    finally:
        if proc.poll() is None:
            proc.kill()
        server.shutdown()
