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
  127.0.0.1:2501  SMTP       Postfix banner, accepts any RCPT (open relay)
  127.0.0.1:2502  SMTP       Postfix banner, rejects relaying (no finding)
  127.0.0.1:2503  CRASHY     echo service that DIES on a >1024-byte payload
                             (demonstrates the robustness module finding a crash)

Usage:  python3 tools/mocklab/mock_services.py
Then:   ./build/apps/sleipnir/sleipnir scan 127.0.0.1 \
            -p 2101,2102,2201,2501,2502,2503,8080,8443
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
                    b"QUIT": b"221 Bye\r\n",
                }
                self.request.sendall(replies.get(cmd, b"502 Command not implemented\r\n"))
                if cmd == b"QUIT":
                    break
            except OSError:
                break


class SmtpStrictHandler(SmtpRelayHandler):
    RCPT_REPLY = b"554 Relay access denied\r\n"


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


SERVICES = [
    ("ssh", 2201, SshHandler),
    ("ftp-vuln", 2101, FtpHandler),
    ("ftp-anon", 2102, FtpAnonHandler),
    ("http", 8080, LabHTTPRequestHandler, LabHTTPServer),
    ("https", 8443, LabHTTPRequestHandler, LabHTTPServer),
    ("smtp-relay", 2501, SmtpRelayHandler),
    ("smtp-strict", 2502, SmtpStrictHandler),
    ("crashy-echo", 2503, EchoCrashHandler, CrashyTCPServer),
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
    servers = []
    for entry in SERVICES:
        name, port, handler = entry[0], entry[1], entry[2]
        server_cls = entry[3] if len(entry) > 3 else socketserver.ThreadingTCPServer
        srv = server_cls((HOST, port), handler)
        if name == "https":
            cert, key = ensure_tls_cert()
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
