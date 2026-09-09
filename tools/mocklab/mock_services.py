#!/usr/bin/env python3
"""Sleipnir mock lab: intentionally vulnerable test services on localhost.

Every listener emulates a real service badly enough to trip the scanner:

  127.0.0.1:2201  SSH        banner SSH-2.0-OpenSSH_7.2p2  -> CVE-2024-6387 etc.
  127.0.0.1:2101  FTP        vsftpd 2.3.4                  -> CVE-2011-2523
  127.0.0.1:2102  FTP        vsftpd 3.0.2, anonymous login allowed
  127.0.0.1:8080  HTTP       Server: Apache/2.4.49, root dir listing,
                             exposed /.git/HEAD and /.env  -> CVE-2021-41773
  127.0.0.1:8443  HTTPS      same Apache 2.4.49 web app over TLS with a
                             self-signed, almost-expired certificate whose
                             CN (mock.lab) does not match the scan target
  127.0.0.1:8081  WordPress  WordPress 5.8.1 on PHP 7.2.24 behind nginx
                             1.18.0, REST user enumeration, CORS reflection
  127.0.0.1:6380  Redis      unauthenticated Redis 6.0.16   -> CVE-2022-0543
  127.0.0.1:2375  Docker     Docker Engine API without TLS/auth (root-equivalent)
  127.0.0.1:2501  SMTP       Postfix banner, accepts any RCPT (open relay),
                             VRFY confirms mailboxes (enumeration)
  127.0.0.1:2502  SMTP       Postfix banner, relay closed, VRFY disabled
                             (negative test: no findings)
  127.0.0.1:2503  CRASHY     echo service that DIES on a >1024-byte payload
                             (demonstrates the robustness module finding a crash)

Usage:  python3 tools/mocklab/mock_services.py
Then:   ./build/apps/sleipnir/sleipnir scan 127.0.0.1 \
            -p 2101,2102,2201,2375,2501,2502,2503,6380,8080,8081,8443
"""

import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import os
from http.server import BaseHTTPRequestHandler

HOST = "127.0.0.1"


class BannerHandler(socketserver.BaseRequestHandler):
    """Reads and discards input; sends a static banner on connect."""

    BANNER = b""

    def handle(self):
        try:
            if self.BANNER:
                self.request.sendall(self.BANNER)
            while True:
                data = self.request.recv(1024)
                if not data:
                    break
        except OSError:
            pass


class SshHandler(BannerHandler):
    BANNER = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n"


class FtpHandler(BannerHandler):
    BANNER = b"220 (vsFTPd 2.3.4)\r\n"

    def handle(self):
        self.request.sendall(self.BANNER)
        while True:
            try:
                data = self.request.recv(1024)
                if not data:
                    break
                cmd = data.split(b" ")[0].strip().upper()
                replies = {
                    b"USER": b"331 Please specify the password.\r\n",
                    b"PASS": b"530 Login incorrect.\r\n",
                    b"QUIT": b"221 Goodbye.\r\n",
                }
                self.request.sendall(replies.get(cmd, b"502 Command not implemented.\r\n"))
                if cmd == b"QUIT":
                    break
            except OSError:
                break


class FtpAnonHandler(FtpHandler):
    BANNER = b"220 (vsFTPd 3.0.2)\r\n"

    def handle(self):
        self.request.sendall(self.BANNER)
        while True:
            try:
                data = self.request.recv(1024)
                if not data:
                    break
                cmd = data.split(b" ")[0].strip().upper()
                replies = {
                    b"USER": b"331 Please specify the password.\r\n",
                    b"PASS": b"230 Login successful.\r\n",  # anonymous!
                    b"QUIT": b"221 Goodbye.\r\n",
                }
                self.request.sendall(replies.get(cmd, b"502 Command not implemented.\r\n"))
                if cmd == b"QUIT":
                    break
            except OSError:
                break


class SmtpRelayHandler(BannerHandler):
    BANNER = b"220 mail.lab ESMTP Postfix (Ubuntu)\r\n"

    RCPT_REPLY = b"250 OK\r\n"  # accepts anything -> open relay
    VRFY_REPLY = b"252 2.0.0 root\r\n"  # VRFY confirms mailbox -> enumeration

    def handle(self):
        self.request.sendall(self.BANNER)
        while True:
            try:
                data = self.request.recv(1024)
                if not data:
                    break
                cmd = data.split()[0].strip().upper()
                replies = {
                    b"HELO": b"250 mail.lab\r\n",
                    b"EHLO": b"250-mail.lab\r\n250 OK\r\n",
                    b"MAIL": b"250 OK\r\n",
                    b"RCPT": self.RCPT_REPLY,
                    b"VRFY": self.VRFY_REPLY,
                    b"QUIT": b"221 Bye\r\n",
                }
                self.request.sendall(replies.get(cmd, b"502 Command not implemented\r\n"))
                if cmd == b"QUIT":
                    break
            except (OSError, IndexError):
                break


class SmtpStrictHandler(SmtpRelayHandler):
    RCPT_REPLY = b"554 Relay access denied\r\n"
    VRFY_REPLY = b"502 5.5.1 VRFY command is disabled\r\n"


class CrashedServer(Exception):
    pass


class EchoCrashHandler(socketserver.StreamRequestHandler):
    """Echoes input back; a payload over 1024 bytes 'crashes' the service
    by raising inside the handler with the shared server shutting down."""

    def handle(self):
        try:
            data = self.request.recv(4096)
            if len(data) > 1024:
                raise CrashedServer("buffer overflow simulation")
            if data:
                self.request.sendall(data)
        except OSError:
            pass


class CrashyTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # simulate a service process dying on the crash payload
        import sys
        exc = sys.exception()
        if isinstance(exc, CrashedServer):
            print("[mocklab] crashy-echo: simulated crash, shutting down")
            self.shutdown()
        else:
            super().handle_error(request, client_address)


class LabHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class LabHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49 (Unix)"  # deliberately old -> CVE-2021-41773
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                "<html><head><title>Index of /</title></head><body>"
                "<h1>Index of /</h1><table>"
                '<tr><td><a href="../">Parent Directory</a></td></tr>'
                '<tr><td><a href="secret.txt">secret.txt</a></td></tr>'
                '<tr><td><a href="backup/">backup/</a></td></tr>'
                "</table></body></html>"
            ).encode()
            self._send(200, body)
        elif path == "/.git/HEAD":
            self._send(200, b"ref: refs/heads/main\n")
        elif path == "/.env":
            self._send(
                200,
                b"SECRET_KEY=hunter2\nDB_PASSWORD=admin123\nAPI_TOKEN=tok_123\n",
            )
        else:
            self._send(404, b"Not Found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # silence request logging
        pass


class RedisLabHandler(socketserver.StreamRequestHandler):
    """Minimal RESP implementation: an unauthenticated Redis 6.0.16 whose
    INFO replies with the version (CVE-2022-0543 territory)."""

    INFO_BODY = (
        b"# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\n"
        b"os:Linux 5.4.0 x86_64\r\nrun_id:mocklab\r\ntcp_port:6380\r\n"
        b"uptime_in_seconds:42\r\n"
    )

    def handle(self):
        try:
            self.request.settimeout(2)
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                cmd = data.split(b"\r\n")[0].strip().upper()
                if cmd.startswith(b"PING"):
                    self.request.sendall(b"+PONG\r\n")
                elif cmd.startswith(b"INFO"):
                    body = self.INFO_BODY
                    self.request.sendall(
                        b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n"
                    )
                elif cmd.startswith(b"QUIT"):
                    self.request.sendall(b"+OK\r\n")
                    break
                else:
                    self.request.sendall(
                        b"-ERR unknown command '" + cmd + b"'\r\n"
                    )
        except OSError:
            pass


class DockerApiHandler(BaseHTTPRequestHandler):
    """Docker Engine API on plain HTTP without TLS or auth: the root-equivalent
    access the docker_api_unauth plugin should report."""

    server_version = "Docker/20.10.12 (linux)"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/version":
            body = (
                b'{"Platform":{"Name":"Docker Engine - Community"},'
                b'"Version":"20.10.12","ApiVersion":"1.41","Os":"linux",'
                b'"Arch":"amd64","KernelVersion":"5.4.0"}'
            )
            self._send(200, body, "application/json")
        elif path == "/containers/json":
            body = (
                b'[{"Id":"a1b2c3","Names":[{"Name":"/web"}],'
                b'"Image":"nginx:1.21","Status":"Up 3 days"}]'
            )
            self._send(200, body, "application/json")
        else:
            self._send(404, b'{"message":"page not found"}', "application/json")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class WordPressHandler(BaseHTTPRequestHandler):
    """A WordPress 5.8.1 on PHP 7.2.24 behind nginx 1.18.0: every component
    has a known CVE, and the REST API leaks user logins."""

    server_version = "nginx/1.18.0"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                b"<!DOCTYPE html><html><head>"
                b'<meta name="generator" content="WordPress 5.8.1" />'
                b"<title>Mock WP</title></head><body>"
                b'<link rel="stylesheet" href="/wp-content/themes/mock/style.css">'
                b"<p>Welcome to the mock WordPress site.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "PHP/7.2.24")
            # deliberately reflects any Origin (CORS misconfiguration)
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/wp-json/wp/v2/users":
            body = (
                b'[{"id":1,"name":"admin","slug":"admin"},'
                b'{"id":2,"name":"Editor","slug":"editor"},'
                b'{"id":3,"name":"dev","slug":"dev"}]'
            )
            self._send(200, body)
        else:
            self._send(404, b"Not Found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", "PHP/7.2.24")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class SpaHandler(BaseHTTPRequestHandler):
    """A generic JS-SPA backend: GraphQL with introspection, Spring-style
    actuator, OpenAPI docs, a shipped package.json and a search endpoint
    that breaks on quotes."""

    server_version = "mock-spa"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/":
            body = (
                b"<!DOCTYPE html><html><head><title>Mock SPA</title></head>"
                b"<body><app-root></app-root>"
                b'<script src="/main.js"></script></body></html>'
            )
            self._send(200, body, "text/html")
        elif path == "/graphql":
            if "__schema" in query:
                body = (
                    b'{"data":{"__schema":{"types":['
                    b'{"kind":"SCALAR","name":"String"},'
                    b'{"kind":"OBJECT","name":"User"},'
                    b'{"kind":"OBJECT","name":"Product"}]}}}'
                )
                self._send(200, body, "application/json")
            else:
                self._send(400,
                           b'{"errors":[{"message":"GET query missing."}]}',
                           "application/json")
        elif path == "/actuator":
            body = (
                b'{"_links":{"self":{"href":"/actuator"},'
                b'"health":{"href":"/actuator/health"},'
                b'"env":{"href":"/actuator/env"}}}'
            )
            self._send(200, body, "application/json")
        elif path == "/v3/api-docs":
            body = (
                b'{"openapi":"3.0.1","info":{"title":"Mock API","version":"1.0"},'
                b'"paths":{"/users":{"get":{}},"/admin":{"get":{}}}}'
            )
            self._send(200, body, "application/json")
        elif path == "/package.json":
            body = (
                b'{"name":"mock-spa","version":"1.2.3",'
                b'"dependencies":{"express":"^4.18.0","sqlite3":"^5.0.2"}}'
            )
            self._send(200, body, "application/json")
        elif path == "/search":
            if "'" in query:
                body = (
                    b'{"errors":[{"message":"SQLITE_ERROR: near \')\':'
                    b' syntax error"}]}'
                )
                self._send(500, body, "application/json")
            else:
                self._send(200, b'{"results":[]}', "application/json")
        else:
            self._send(404, b'{"message":"not found"}', "application/json")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


SERVICES = [
    ("ssh", 2201, SshHandler),
    ("ftp-vuln", 2101, FtpHandler),
    ("ftp-anon", 2102, FtpAnonHandler),
    ("http", 8080, LabHTTPRequestHandler, LabHTTPServer),
    ("https", 8443, LabHTTPRequestHandler, LabHTTPServer),
    ("smtp-relay", 2501, SmtpRelayHandler),
    ("smtp-strict", 2502, SmtpStrictHandler),
    ("crashy-echo", 2503, EchoCrashHandler, CrashyTCPServer),
    ("redis", 6380, RedisLabHandler),
    ("docker-api", 2375, DockerApiHandler, LabHTTPServer),
    ("wordpress", 8081, WordPressHandler, LabHTTPServer),
    ("spa", 8082, SpaHandler, LabHTTPServer),
]


def ensure_tls_cert():
    """Generates a deliberately flawed self-signed certificate (CN=mock.lab,
    1-day validity) so the TLS checks have something to find."""
    certdir = os.path.join(tempfile.gettempdir(), "sleipnir_mocklab_certs")
    os.makedirs(certdir, exist_ok=True)
    cert = os.path.join(certdir, "server.pem")
    key = os.path.join(certdir, "server.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", cert, "-days", "1",
                "-subj", "/CN=mock.lab/O=Sleipnir Mock Lab",
            ],
            check=True,
            capture_output=True,
        )
    return cert, key


def main():
    # generate the TLS certificate before any listener starts, so a scan
    # launched right after the lab never races the cert generation
    cert, key = ensure_tls_cert()

    servers = []
    for entry in SERVICES:
        name, port, handler = entry[0], entry[1], entry[2]
        server_cls = entry[3] if len(entry) > 3 else socketserver.ThreadingTCPServer
        srv = server_cls((HOST, port), handler)
        if name == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        servers.append(srv)
        print(f"[mocklab] {name:12s} listening on {HOST}:{port}")

    print("[mocklab] ready. Ctrl+C to stop all services.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[mocklab] shutting down")
        for srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    main()
