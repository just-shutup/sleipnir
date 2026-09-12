#!/usr/bin/env python3
"""Sleipnir mock lab: intentionally vulnerable test services on localhost.

Every listener emulates a real service badly enough to trip the scanner:

  127.0.0.1:2201  SSH        banner SSH-2.0-OpenSSH_7.2p2  -> CVE-2024-6387 etc.
  127.0.0.1:2101  FTP        vsftpd 2.3.4                  -> CVE-2011-2523
  127.0.0.1:2102  FTP        vsftpd 3.0.2, anonymous login allowed
  127.0.0.1:8080  HTTP       Server: Apache/2.4.49, root dir listing,
                             exposed /.git/HEAD and /.env, and the
                             single-encoded .%2e traversal is open
                             -> CVE-2021-41773 CONFIRMED by active check
  127.0.0.1:8443  HTTPS      Apache/2.4.50 over TLS (self-signed, almost
                             expired cert, CN mismatch): .%2e is blocked
                             but the double-encoded .%%32%65 bypass works
                             -> CVE-2021-42013 CONFIRMED over the TLS
                             transport
  127.0.0.1:8081  WordPress  WordPress 4.7 on PHP/5.4.1 behind nginx
                             1.18.0, REST user enumeration, CORS reflection;
                             php-cgi runs query-string switches -> ?-s dumps
                             highlighted source
                             -> CVE-2012-1823 and CVE-2017-5487 CONFIRMED
  127.0.0.1:8082  SPA        GraphQL introspection, actuator, OpenAPI, SQL
                             errors; the Java backend evaluates JNDI
                             expressions from request headers
                             -> Log4Shell canary CONFIRMED
  127.0.0.1:8083  VulnWeb    reflected XSS, CSRF-less POST /login, path
                             traversal /profile?page, open redirect
                             /redirect?to, template evaluation /render?tpl
                             (SSTI), server-side fetch /fetch?url (SSRF,
                             stays "potential"), external-entity XML on
                             POST /comment (XXE)
  127.0.0.1:8084  Apache-hardened  Apache/2.4.49 with traversal locked
                             down: version still matches CVE-2021-41773,
                             the check fails -> stays "potential"
                             (negative stand)
  127.0.0.1:8085  PHP-hardened    WordPress 4.7 on PHP/5.4.1, php-cgi
                             query-string flaw patched AND the REST users
                             endpoint requires auth -> CVE-2012-1823 and
                             CVE-2017-5487 stay "potential"
                             (negative stand)
  127.0.0.1:8086  Grafana-hardened  Grafana v8.3.0, plugin route traversal
                             fixed -> CVE-2021-43798 stays "potential"
                             (negative stand)
  127.0.0.1:8087  Webmin-hardened  MiniServ/1.910, password_change.cgi
                             rejects unauthenticated calls -> CVE-2019-15107
                             stays "potential" (negative stand)
  127.0.0.1:8088  Grafana     Grafana v8.3.0, /public/plugins/..%2f
                             traversal open -> CVE-2021-43798 CONFIRMED
  127.0.0.1:8089  Webmin     MiniServ/1.910, password_change.cgi runs the
                             injected command -> CVE-2019-15107 CONFIRMED
  127.0.0.1:8090  Elasticsearch  1.4.0 with Groovy script_fields enabled
                             -> CVE-2015-1427 CONFIRMED
  127.0.0.1:8091  ES-hardened    same 1.4.0 with inline scripts disabled
                             -> CVE-2015-1427 stays "potential"
                             (negative stand)
  127.0.0.1:8092  BIG-IP     BigIP 13.1.0, TMUI fileRead traversal open
                             -> CVE-2020-5902 CONFIRMED
   127.0.0.1:8093  BIG-IP-hardened  same 13.1.0 with the TMUI hotfix
                              -> CVE-2020-5902 stays "potential"
                              (negative stand)
   127.0.0.1:8094  Jenkins    2.426, CLI argument expansion over chunked
                              POST reads /etc/passwd
                              -> CVE-2024-23897 CONFIRMED via check script
   127.0.0.1:8095  Jenkins-hardened  same 2.426 with the CLI fixed
                              -> CVE-2024-23897 stays "potential"
                              (negative stand)
   127.0.0.1:2375  Docker     Docker Engine API without TLS/auth (root-equivalent)
   127.0.0.1:2202  SSH-weak   MockSSH_Weak1.0 advertises weak kex/ciphers
                              (dh-group1-sha1, 3des-cbc, arcfour)
                              -> SSH audit module flags weak algorithms
   127.0.0.1:2203  SSH-strong  MockSSH_Strong1.0 with only modern algorithms
                              -> SSH audit module finds no weak algorithms
                              (negative stand)
   127.0.0.1:6382  redis-pw    Redis 6.0.16 with requirepass (default creds)
                              -> default-creds check against password-protected instance
   127.0.0.1:3307  mysql-def  MySQL 5.7.33-log accepting root/root
                              -> default-creds check for MySQL
  127.0.0.1:2501  SMTP       Postfix banner, accepts any RCPT (open relay),
                             VRFY confirms mailboxes (enumeration)
  127.0.0.1:2502  SMTP       Postfix banner, relay closed, VRFY disabled
                             (negative test: no findings)
  127.0.0.1:2503  CRASHY     echo service that DIES on a >1024-byte payload
                             (demonstrates the robustness module finding a crash)
  127.0.0.1:1900/udp SSDP    answers M-SEARCH (UPnP device discovery)
  127.0.0.1:5353/udp mDNS    answers PTR queries for _dns-sd services
  127.0.0.1:11211/udp memcached UDP-framed VERSION reply
  [::1]:2201,[::1]:8080     the SSH/HTTP pair bound on IPv6 loopback
                             (for `scan ::1`)

Usage:  python3 tools/mocklab/mock_services.py
Then:   ./build/apps/sleipnir/sleipnir scan 127.0.0.1 \
            -p 2101,2102,2201,2202,2203,2375,2501,2502,2503,3307,6380,6381,6382,8080-8095,8443
        ./build/apps/sleipnir/sleipnir scan 127.0.0.1 -p 1900 --udp \
            --udp-ports 1900,5353,11211,161
        ./build/apps/sleipnir/sleipnir scan 127.0.0.1 -p 2202,2203 --ssh-audit
        ./build/apps/sleipnir/sleipnir scan 127.0.0.1 -p 3307,6382 \
            --brute-default-creds
"""

import html
import re
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import os
from http.server import BaseHTTPRequestHandler
from urllib.parse import unquote, urlsplit

HOST = "127.0.0.1"

# /etc/passwd served by every intentionally traversal-vulnerable handler
PASSWD_BODY = (
    b"root:x:0:0:root:/root:/bin/bash\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    b"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
)


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
    # which URL-encoded traversal this build still falls for:
    #   "single" -> CVE-2021-41773 (.%2e), "double" -> CVE-2021-42013
    #   (.%%32%65), None -> patched/hardened
    traversal_vuln = "single"

    def do_GET(self):
        path = self.path.split("?")[0]
        low = self.path.lower()
        if any(p in low for p in (".%2e", "%2e%2e", "..%2f", "..%5c",
                                  "%%32%65")):
            # traversal territory: CVE-2021-41773 / CVE-2021-42013
            if (self.traversal_vuln == "single" and
                    any(p in low for p in (".%2e", "%2e%2e", "..%2f",
                                           "..%5c"))):
                self._send(200, PASSWD_BODY)
            elif self.traversal_vuln == "double" and "%%32%65" in low:
                self._send(200, PASSWD_BODY)
            else:
                self._send(404, b"Not Found")
            return
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


class ApacheDoubleTraversalHandler(LabHTTPRequestHandler):
    """Apache 2.4.50: the .%2e fix is incomplete, the double-encoded
    .%%32%65 bypass (CVE-2021-42013) still escapes the document root."""

    server_version = "Apache/2.4.50 (Unix)"
    traversal_vuln = "double"


class ApacheHardenedHandler(LabHTTPRequestHandler):
    """Apache 2.4.49 with the traversal backported/hardened (negative
    stand): the version still matches CVE-2021-41773 but every traversal
    path is rejected, so the active check must fail."""

    traversal_vuln = None

    def do_GET(self):
        path = self.path.split("?")[0]
        low = self.path.lower()
        if any(p in low for p in (".%2e", "%2e%2e", "..%2f", "..%5c",
                                  "%%32%65")):
            self._send(403, b"Forbidden")
            return
        if path == "/":
            self._send(200, b"<html><body><h1>It works!</h1></body></html>")
        else:
            self._send(404, b"Not Found")


class RedisLabHandler(socketserver.StreamRequestHandler):
    """Minimal RESP implementation: an unauthenticated Redis 6.0.16 whose
    INFO replies with the version (CVE-2022-0543 territory). The Lua
    sandbox is leaky: EVAL "return tostring(package)" answers with a table
    address instead of nil."""

    INFO_BODY = (
        b"# Server\r\nredis_version:6.0.16\r\nredis_mode:standalone\r\n"
        b"os:Linux 5.4.0 x86_64\r\nrun_id:mocklab\r\ntcp_port:6380\r\n"
        b"uptime_in_seconds:42\r\n"
    )
    lua_sandbox_leaky = True

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
                elif data.startswith(b"*") and b"EVAL" in data:
                    # CVE-2022-0543: the Lua sandbox exposes `package` on
                    # vulnerable Debian builds; the patched one returns nil
                    if self.lua_sandbox_leaky and b"package" in data:
                        self.request.sendall(
                            b"$21\r\ntable: 0x7f8a1c00b3d0\r\n"
                        )
                    else:
                        self.request.sendall(b"$3\r\nnil\r\n")
                elif cmd.startswith(b"QUIT"):
                    self.request.sendall(b"+OK\r\n")
                    break
                else:
                    self.request.sendall(
                        b"-ERR unknown command '" + cmd + b"'\r\n"
                    )
        except OSError:
            pass


class RedisHardenedHandler(RedisLabHandler):
    """Redis 6.0.16 with the Lua sandbox fixed (negative stand): EVAL
    answers 'nil', so the CVE-2022-0543 check script must fail."""

    lua_sandbox_leaky = False


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
    """A WordPress 4.7 on PHP/5.4.1 behind nginx 1.18.0: every component
    has a known CVE, the REST API leaks user logins (CVE-2017-5487, fixed
    only in 4.7.1), and php-cgi executes query-string switches
    (CVE-2012-1823): ?-s dumps highlighted source."""

    server_version = "nginx/1.18.0"
    php_version = "PHP/5.4.1"
    php_cgi_vulnerable = True
    rest_users_exposed = True

    def do_GET(self):
        path, _, query = self.path.partition("?")
        # CVE-2017-5487: the REST API lists users without authentication
        if path in ("/wp-json/wp/v2/users", "/") and (
            path == "/wp-json/wp/v2/users"
            or query.startswith("rest_route=/wp/v2/users")
        ):
            if self.rest_users_exposed:
                body = (
                    b'[{"id":1,"name":"admin","slug":"admin",'
                    b'"user_roles":["administrator"]},'
                    b'{"id":2,"name":"Editor","slug":"editor"},'
                    b'{"id":3,"name":"dev","slug":"dev"}]'
                )
                self._send(200, body)
            else:
                self._send(
                    401,
                    b'{"code":"rest_cannot_list_users","message":"Sorry, '
                    b'you are not allowed to list users."}',
                )
            return
        # CVE-2012-1823: php-cgi treats the query string as CLI switches;
        # -s prints the script source with syntax highlighting.
        if self.php_cgi_vulnerable and query.strip() in ("-s", "-s&"):
            body = (
                b'<code><span style="color: #000000">\n'
                b'<span style="color: #0000BB">&lt;?php\n'
                b"/* mocked php-cgi source disclosure (CVE-2012-1823) */\n"
                b'echo "WordPress mock";\n'
                b"</span>\n</code>"
            )
            self._send(200, body)
            return
        if path == "/":
            body = (
                b"<!DOCTYPE html><html><head>"
                b'<meta name="generator" content="WordPress 4.7" />'
                b"<title>Mock WP</title></head><body>"
                b'<link rel="stylesheet" href="/wp-content/themes/mock/style.css">'
                b"<p>Welcome to the mock WordPress site.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", self.php_version)
            # deliberately reflects any Origin (CORS misconfiguration)
            origin = self.headers.get("Origin")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._send(404, b"Not Found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", self.php_version)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class PhpCgiHardenedHandler(WordPressHandler):
    """The same WordPress 4.7 / PHP/5.4.1 stack with the php-cgi
    query-string flaw patched AND the REST users endpoint locked down
    (negative stand): both CVE-2012-1823 and CVE-2017-5487 checks must fail
    and the findings stay potential."""

    php_cgi_vulnerable = False
    rest_users_exposed = False


class SpaHandler(BaseHTTPRequestHandler):
    """A generic JS-SPA backend: GraphQL with introspection, Spring-style
    actuator, OpenAPI docs, a shipped package.json, a search endpoint that
    breaks on quotes — and a Java backend that evaluates JNDI expressions
    from request headers (Log4Shell, CVE-2021-44228)."""

    server_version = "mock-spa"

    def _log4shell_hit(self):
        """A ${jndi:...} expression in User-Agent/Referer/X-Api-Version is
        evaluated: the naming lookup fails and the error names the canary
        host (without echoing the raw expression)."""
        for h in ("User-Agent", "Referer", "X-Api-Version"):
            v = self.headers.get(h) or ""
            m = re.search(r"\$\{jndi:(?:dns|ldap|rmi|iiop)://([^/}\s]+)", v)
            if m:
                host = m.group(1)
                body = (
                    "HTTP 500 Internal Server Error\n\n"
                    "javax.naming.CommunicationException: " + host +
                    " [Root exception is java.net.UnknownHostException: " +
                    host + "]"
                ).encode()
                self._send(500, body, "text/plain")
                return True
        return False

    def do_GET(self):
        if self._log4shell_hit():
            return
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


class VulnWebHandler(BaseHTTPRequestHandler):
    """A tiny deliberately vulnerable web app for the crawler:
    reflected XSS in /search, POST /login without a CSRF token,
    path traversal in /profile?page, an open redirect /redirect?to,
    a template engine behind /render?tpl (SSTI), a server-side fetch
    in /fetch?url (SSRF, only provable out-of-band -> stays potential)
    and an XML API on POST /comment that resolves external entities (XXE)."""

    server_version = "vulnweb/1.0"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = dict(
            kv.split("=", 1) for kv in query.split("&") if "=" in kv
        )
        if path == "/":
            xfh = self.headers.get("X-Forwarded-Host")
            base_tag = (
                '<base href="http://%s/">' % xfh if xfh else ""
            )
            body = (
                b"<!DOCTYPE html><html><head><title>VulnWeb</title>"
                + base_tag.encode() +
                b"</head><body>"
                b"<h1>VulnWeb</h1>"
                b"<a href='/search?q=hello'>Search</a><br>"
                b"<a href='/profile?page=welcome'>Profile</a><br>"
                b"<a href='/redirect?to=%2Fhome'>Home via redirect</a><br>"
                b"<a href='/render?tpl=Welcome'>Render</a><br>"
                b"<a href='/fetch?url=http%3A%2F%2Fexample.test%2Ffeed'>"
                b"Fetch feed</a><br>"
                b"<a href='/item?id=1'>Item</a><br>"
                b"<a href='/report?id=1'>Report</a><br>"
                b"<a href='/ping?host=127.0.0.1'>Ping</a><br>"
                b"<a href='https://example.org/external'>External link</a>"
                b"<form action='/login' method='POST'>"
                b"<input name='user'><input type='password' name='pass'>"
                b"<button>Login</button></form>"
                b"<form action='/comment' method='POST'>"
                b"<input type='hidden' name='csrf_token' value='t123'>"
                b"<input name='text'><button>Comment</button></form>"
                b"</body></html>"
            )
            self._send(200, body, "text/html")
        elif path == "/item":
            # boolean-based SQLi: '1'='1 answers like the baseline row,
            # '1'='2 returns an empty result set
            item_id = params.get("id", "1")
            if "'" in item_id:
                if "'1'='1" in item_id:
                    body = b"<html><body>Item 1: standard issue widget"
                else:
                    body = b"<html><body>Item not found"
                body += b"</body></html>"
                self._send(200, body, "text/html")
            elif item_id == "1":
                self._send(
                    200, b"<html><body>Item 1: standard issue widget"
                         b"</body></html>", "text/html")
            else:
                self._send(
                    200, b"<html><body>Item not found</body></html>",
                    "text/html")
        elif path == "/report":
            # time-based SQLi: the backend executes injected SLEEP /
            # WAITFOR / pg_sleep expressions (3 s here, so default
            # timeouts still observe the delay)
            rid = params.get("id", "1")
            if ("SLEEP(5)" in rid or "pg_sleep" in rid
                    or "WAITFOR" in rid):
                time.sleep(3)
                self._send(200, b"<html><body>Report generated"
                                 b"</body></html>", "text/html")
            else:
                body = ("<html><body>Report " + html.escape(rid) +
                        " generated</body></html>").encode()
                self._send(200, body, "text/html")
        elif path == "/ping":
            # blind command injection: a shell-style sleep command in the
            # value is executed (3 s delay in the mock); SQL payloads
            # (SLEEP(5), pg_sleep) are NOT executed by this endpoint
            target = params.get("host", "")
            is_cmd = (";" in target or "|" in target or "&&" in target) and (
                "sleep" in target.lower()
            )
            if is_cmd:
                time.sleep(3)
                self._send(200, b"<html><body>PING done</body></html>",
                           "text/html")
            else:
                body = ("<html><body>PING " + html.escape(target) +
                        " ok</body></html>").encode()
                self._send(200, body, "text/html")
        elif path == "/search":
            # reflects the q parameter unencoded (XSS)
            q = params.get("q", "")
            body = (
                b"<html><body><h1>Results for: " + q.encode() + b"</h1>"
                b"<p>nothing found</p></body></html>"
            )
            self._send(200, body, "text/html")
        elif path == "/render":
            # server-side template engine: evaluates the tpl parameter
            tpl = unquote(params.get("tpl", ""))
            if "{{7*'7'}}" in tpl:
                result = "7777777"  # Jinja2/Twig-style string arithmetic
            elif "SLEIPNSTI${7*7}SLEIPNSTI" in tpl:
                result = "SLEIPNSTI49SLEIPNSTI"  # Freemarker/Mako style
            else:
                result = html.escape(tpl)  # plain values pass through safely
            body = ("<html><body><h1>Rendered: " + result +
                    "</h1></body></html>").encode()
            self._send(200, body, "text/html")
        elif path == "/fetch":
            # server-side fetch: any host is attempted, none resolve in the
            # lab -> the error names the requested host (SSRF evidence)
            target = unquote(params.get("url", ""))
            try:
                parsed = urlsplit(target)
            except ValueError:
                parsed = None
            if parsed and parsed.scheme in ("http", "https") and parsed.hostname:
                body = ("<html><body><h1>Fetch failed</h1>"
                        "<p>Proxy error: could not resolve host " +
                        parsed.hostname + "</p></body></html>").encode()
                self._send(502, body, "text/html")
            else:
                self._send(400,
                           b"<html><body><p>Invalid URL</p></body></html>",
                           "text/html")
        elif path == "/profile":
            page = params.get("page", "welcome")
            if "../" in page:
                body = (
                    b"<html><body><pre>root:x:0:0:root:/root:/bin/bash\n"
                    b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre>"
                    b"</body></html>"
                )
                self._send(200, body, "text/html")
            else:
                self._send(200, b"<html><body>Profile page</body></html>",
                           "text/html")
        elif path == "/redirect":
            self.send_response(302)
            self.send_header("Location", params.get("to", "/"))
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0]
        if path == "/comment":
            # XML API with a parser that resolves external entities (XXE):
            # the entity content comes back in-band
            if b"<!ENTITY" in body and b"file:///" in body:
                self._send(200,
                           b"<response><data>" + PASSWD_BODY +
                           b"</data></response>", "application/xml")
            else:
                self._send(200, b"<response><data>stored</data></response>",
                           "application/xml")
        elif path == "/login":
            self._send(200, b"<html><body>Welcome back!</body></html>",
                       "text/html")
        else:
            self._send(200, b"ok", "text/plain")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


# ---------------------------------------------------------------------------
# Verification-stage stands: Grafana (CVE-2021-43798) and Webmin
# (CVE-2019-15107), each in a vulnerable and a hardened variant.
# ---------------------------------------------------------------------------

GRAFANA_LOGIN = (
    b"<!DOCTYPE html><html><head><title>Grafana</title></head><body>"
    b"<div class='login-form'><h3>Welcome to Grafana</h3>"
    b"<form action='/login' method='POST'>"
    b"<input name='user'><input type='password' name='password'>"
    b"<button>Log in</button></form></div>"
    b"<footer>Grafana v8.3.0</footer></body></html>"
)


class GrafanaHandler(BaseHTTPRequestHandler):
    """Grafana 8.3.0: the /public/plugins/<plugin>/..%2f path traversal
    (CVE-2021-43798) serves files outside the plugin directory."""

    traversal_vulnerable = True

    def version_string(self):
        return ""  # real Grafana sends no Server header

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/login"):
            self._send(200, GRAFANA_LOGIN, "text/html")
        elif path.startswith("/public/plugins/"):
            if self.traversal_vulnerable and "..%2f" in self.path.lower():
                self._send(200, PASSWD_BODY, "text/plain")
            else:
                self._send(404, b'{"message":"Not found"}',
                           "application/json")
        else:
            self._send(404, b'{"message":"Not found"}', "application/json")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class GrafanaHardenedHandler(GrafanaHandler):
    """Grafana 8.3.0 with the plugin route fixed (negative stand): the
    version still matches CVE-2021-43798 but the traversal 404s."""

    traversal_vulnerable = False


class WebminHandler(BaseHTTPRequestHandler):
    """Webmin 1.910 behind MiniServ: password_change.cgi runs the command
    injected into the 'old' parameter before authentication
    (CVE-2019-15107). The injected 'cat /etc/passwd' is read-only."""

    injectable = True

    def version_string(self):
        return "MiniServ/1.910"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                b"<!DOCTYPE html><html><head><title>Login to Webmin</title>"
                b"</head><body><h1>Webmin</h1>"
                b"<form action='/session_login.cgi' method='POST'>"
                b"<input name='user'><input type='password' name='pass'>"
                b"<button>Login</button></form></body></html>"
            )
            self._send(200, body, "text/html")
        else:
            self._send(404, b"Error - Document not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        path = self.path.split("?")[0]
        if path == "/password_change.cgi" and self.injectable:
            decoded = unquote(body.decode("latin-1", "replace"))
            if "cat /etc/passwd" in decoded:
                # command injection: the injected command's output comes
                # back inside the password-change error page
                page = (b"<html><body><h3>Password change failed</h3>"
                        b"<pre>" + PASSWD_BODY + b"</pre></body></html>")
                self._send(200, page, "text/html")
                return
            self._send(401, b"<html><body>Incorrect password</body></html>",
                       "text/html")
        else:
            self._send(401, b"<html><body>Authorization required</body>"
                            b"</html>", "text/html")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class WebminHardenedHandler(WebminHandler):
    """Webmin 1.910 with password_change.cgi hardened (negative stand):
    unauthenticated callers get a 401, the injection never runs."""

    injectable = False


class ElasticsearchHandler(BaseHTTPRequestHandler):
    """Elasticsearch 1.4.0 (CVE-2015-1427 territory): Groovy script_fields
    in search queries are enabled by default, so an inline script is
    evaluated and its result comes back in the response."""

    groovy_enabled = True

    def version_string(self):
        return "Elasticsearch/1.4.0"

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                b'{"status":200,"name":"mock-es","cluster_name":"mocklab",'
                b'"version":{"number":"1.4.0","build_hash":"c59f00b",'
                b'"build_timestamp":"2015-02-11T19:23:31Z",'
                b'"lucene_version":"4.10.2"},'
                b'"tagline":"You Know, for Search"}'
            )
            self._send(200, body)
        else:
            self._send(404, b'{"error":"Not Found","status":404}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.split("?")[0] != "/_search":
            self._send(404, b'{"error":"Not Found","status":404}')
            return
        if self.groovy_enabled and b"script_fields" in body and b"7*7" in body:
            # the inline Groovy expression is evaluated: 7*7 -> 49
            resp = (
                b'{"took":5,"timed_out":false,"hits":{"total":1,'
                b'"hits":[{"_index":"mock","_type":"doc","_id":"1",'
                b'"_score":1.0,"fields":{"slnck":[49]}}]}}'
            )
            self._send(200, resp)
        elif not self.groovy_enabled and b"script_fields" in body:
            self._send(
                400,
                b'{"error":"ElasticsearchException[scripts of type [inline],'
                b' operation [search] and lang [groovy] are disabled]",'
                b'"status":400}',
            )
        else:
            self._send(200, b'{"took":2,"hits":{"total":0,"hits":[]}}')

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class ElasticsearchHardenedHandler(ElasticsearchHandler):
    """Elasticsearch 1.4.0 with dynamic scripting disabled (negative
    stand): the version still matches CVE-2015-1427 but the script_fields
    probe is rejected."""

    groovy_enabled = False


class BigIpHandler(BaseHTTPRequestHandler):
    """F5 BIG-IP 13.1.0 with the pre-CVE-2020-5902 TMUI: the fileRead.jsp
    workspace endpoint serves arbitrary files without authentication."""

    traversal_vulnerable = True

    def version_string(self):
        return "BigIP/13.1.0"

    def do_GET(self):
        path = unquote(self.path)
        if "fileRead.jsp" in path and "fileName=/etc/passwd" in path:
            if self.traversal_vulnerable:
                self._send(200, PASSWD_BODY, "text/plain")
            else:
                self._send(404, b"Object not found", "text/html")
            return
        if path == "/" or path.startswith("/tmui/login.jsp"):
            body = (
                b"<!DOCTYPE html><html><head><title>BIG-IP</title></head>"
                b"<body><h1>BIG-IP Configuration Utility</h1>"
                b"<form action='/tmui/logmein.html' method='POST'>"
                b"<input name='username'><input type='password'"
                b" name='passwd'><button>Log in</button></form>"
                b"</body></html>"
            )
            self._send(200, body, "text/html")
        else:
            self._send(404, b"Object not found", "text/html")

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class BigIpHardenedHandler(BigIpHandler):
    """BIG-IP 13.1.0 with the CVE-2020-5902 hotfix applied (negative
    stand): the traversal still matches by version but fileRead 404s."""

    traversal_vulnerable = False


class JenkinsHandler(BaseHTTPRequestHandler):
    """Jenkins 2.426 (CVE-2024-23897): the /cli endpoint expands leading @
    arguments as file references. The chunked-POST 'help @/etc/passwd'
    command echoes the file content back."""

    cli_vulnerable = True

    def version_string(self):
        return "Jetty/9.4.z-SNAPSHOT"

    def end_headers(self):
        # every answer carries the Jenkins version header (the fingerprint)
        self.send_header("X-Jenkins", "2.426")
        super().end_headers()

    def _read_body(self):
        if (self.headers.get("Transfer-Encoding", "").lower() == "chunked"):
            body = b""
            while True:
                line = self.rfile.readline().strip()
                try:
                    size = int(line.split(b";")[0], 16)
                except ValueError:
                    break
                if size == 0:
                    while True:
                        t = self.rfile.readline()
                        if t in (b"\r\n", b"\n", b""):
                            break
                    break
                body += self.rfile.read(size)
                self.rfile.readline()
            return body
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body = (
                b"<!DOCTYPE html><html><head><title>Dashboard [Jenkins]</title>"
                b"</head><body><h1>Jenkins</h1>"
                b'<a href="/cli">CLI</a></body></html>'
            )
            self._send(200, body)
        elif path == "/cli":
            self._send(200, b"Jenkins CLI: POST commands here")
        else:
            self._send(404, b"Not Found")

    def do_POST(self):
        body = self._read_body()
        path = self.path.split("?")[0]
        if path == "/cli" or path.startswith("/cli?"):
            if self.cli_vulnerable and b"@/etc/passwd" in body:
                # argument expansion reads the file into the command output
                out = b"help: prints usage\n" + PASSWD_BODY
                self._send(200, out)
            else:
                self._send(403, b"Authentication required")
        else:
            self._send(404, b"Not Found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class JenkinsHardenedHandler(JenkinsHandler):
    """Jenkins 2.426 with the CLI argument expansion fixed (negative
    stand): /cli rejects unauthenticated POSTs, the check script fails."""

    cli_vulnerable = False


import base64 as _base64


class AuthAppHandler(BaseHTTPRequestHandler):
    """An application with an area behind a login (for --auth e2e):
    POST /login sets a session cookie, /admin/* requires it (or HTTP
    Basic). The admin search reflects its q parameter — a verified XSS
    that only exists behind the authentication the scanner carries."""

    server_version = "authapp/1.0"

    def _authed(self):
        cookie = self.headers.get("Cookie") or ""
        if "slnsession=authok42" in cookie:
            return True
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Basic "):
            try:
                decoded = _base64.b64decode(auth[6:]).decode()
                if decoded == "admin:s3cret":
                    return True
            except Exception:
                pass
        return False

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = dict(
            kv.split("=", 1) for kv in query.split("&") if "=" in kv
        )
        if path == "/robots.txt":
            body = (
                b"User-agent: *\n"
                b"Disallow: /admin\n"
                b"Disallow: /admin/dashboard\n"
                b"Disallow: /admin/search\n"
                b"Sitemap: http://127.0.0.1:8096/sitemap.xml\n"
            )
            self._send(200, body, "text/plain")
        elif path == "/sitemap.xml":
            body = (
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                b"<url><loc>http://127.0.0.1:8096/</loc></url>"
                b"</urlset>"
            )
            self._send(200, body, "application/xml")
        elif path == "/":
            body = (
                b"<!DOCTYPE html><html><head><title>MockApp</title></head>"
                b"<body><h1>MockApp</h1>"
                b"<form action='/login' method='POST'>"
                b"<input type='hidden' name='csrf_token' value='t9'>"
                b"<input name='user'><input type='password' name='pass'>"
                b"<button>Sign in</button></form></body></html>"
            )
            self._send(200, body, "text/html")
        elif path == "/uploads":
            # hidden path: served (with a session), nothing links to it
            if not self._authed():
                self._redirect("/login")
                return
            self._send(200, b"<html>uploads</html>", "text/html")
        elif path == "/adminer":
            # protected path: 401 for everyone (dirb recon intel)
            self._send(401, b"auth required", "text/plain")
        elif path == "/admin" or path == "/admin/dashboard":
            if not self._authed():
                self._redirect("/login")
                return
            body = (
                b"<!DOCTYPE html><html><body><h1>Admin dashboard</h1>"
                b"<p>SECRET-AREA: db password hunter2</p>"
                b"<a href='/admin/search?q=hello'>Search</a><br>"
                b"<a href='/admin/profile?user=1'>My profile</a>"
                b"</body></html>"
            )
            self._send(200, body, "text/html")
        elif path == "/admin/search":
            if not self._authed():
                self._redirect("/login")
                return
            q = params.get("q", "")
            body = (
                b"<html><body><h1>Results for: " + q.encode() +
                b"</h1></body></html>"
            )
            self._send(200, body, "text/html")
        elif path == "/admin/profile":
            if not self._authed():
                self._redirect("/login")
                return
            user = params.get("user", "1")
            users = {
                "1": ("alice", "alice@example.test", "2021-03-14"),
                "2": ("bob", "bob@example.test", "2022-07-01"),
                "3": ("carol", "carol@example.test", "2023-11-30"),
            }
            who, email, since = users.get(user, ("unknown", "", ""))
            body = (
                "<html><body><h1>User " + html.escape(user) + ": " + who +
                "</h1><p>email: " + email + "</p>"
                "<p>member since: " + since + "</p></body></html>"
            ).encode()
            self._send(200, body, "text/html")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.split("?")[0] == "/login":
            fields = dict(
                kv.split("=", 1) for kv in body.decode().split("&")
                if "=" in kv
            )
            if fields.get("user") == "admin" and fields.get("pass") == "s3cret":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header(
                    "Set-Cookie", "slnsession=authok42; Path=/; HttpOnly"
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(401, b"<html><body>Invalid credentials</body></html>",
                           "text/html")
        else:
            self._send(404, b"not found", "text/plain")

    def _redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


# ---------------------------------------------------------------------------
# UDP services (Sleipnir --udp probe targets; all ports >1024 so the lab
# runs unprivileged)
# ---------------------------------------------------------------------------

class UdpSsdpHandler(socketserver.BaseRequestHandler):
    """SSDP responder: answers M-SEARCH with a rootdevice NOTIFY-style
    response (UPnP devices that leak over multicast unicast too)."""

    def handle(self):
        data, sock = self.request
        if b"M-SEARCH" in data:
            sock.sendto(
                b"HTTP/1.1 200 OK\r\n"
                b"CACHE-CONTROL: max-age=1800\r\n"
                b"DATE: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
                b"EXT:\r\n"
                b"LOCATION: http://127.0.0.1:8080/upnp/root.xml\r\n"
                b"SERVER: Linux/5.4 UPnP/1.0 mocklab/1.0\r\n"
                b"ST: upnp:rootdevice\r\n"
                b"USN: uuid:2fac1234-31f8-11b4-a222-08002b34c003::upnp:rootdevice\r\n"
                b"\r\n",
                self.client_address,
            )


class UdpMdnsHandler(socketserver.BaseRequestHandler):
    """mDNS responder: echoes the question back with the response flag set
    and a PTR answer for _http._tcp.local."""

    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        # response: same id, QR=1, one answer pointing at mocklab.local
        answer = (
            b"\x00\x00"      # name pointer to offset 0
            b"\x00\x0c"      # PTR
            b"\x00\x01"      # IN
            b"\x00\x00\x00\x78"  # TTL 120
            b"\x00\x0a"      # rdlength
            b"\x08mocklab\x05local\x00"
        )
        resp = data[:2] + b"\x84\x00" + b"\x00\x00\x00\x00\x00\x01" + answer
        sock.sendto(resp, self.client_address)


class UdpMemcachedHandler(socketserver.BaseRequestHandler):
    """memcached with UDP framing: replies VERSION to a framed 'version'."""

    def handle(self):
        data, sock = self.request
        if len(data) >= 8 and data[8:].lower().startswith(b"version"):
            header = data[:8]  # echo request id / counters
            sock.sendto(header + b"VERSION 1.6.0\r\n", self.client_address)


class UdpLabServer(socketserver.UDPServer):
    allow_reuse_address = True


class RedisPasswordHandler(RedisLabHandler):
    """Redis 6.0.16 with a password configured (requirepass). On connect
    the server sends '-NOAUTH Authentication required.' for commands that are
    not AUTH, letting the default-creds check exercise password attempts."""

    def handle(self):
        try:
            self.request.settimeout(2)
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                cmd = data.split(b"\r\n")[0].strip().upper()
                if cmd.startswith(b"AUTH"):
                    parts = data.split(b"\r\n")
                    pw = parts[2].strip() if len(parts) > 2 else b""
                    if pw == b"redis":
                        self.request.sendall(b"+OK\r\n")
                    else:
                        self.request.sendall(b"-ERR invalid password\r\n")
                else:
                    self.request.sendall(b"-NOAUTH Authentication required.\r\n")
        except OSError:
            pass


class SshWeakCipherHandler(socketserver.StreamRequestHandler):
    """SSH-2.0 server that advertises weak algorithms in its KEXINIT
    packet so the SSH audit module flags them: weak kex, weak ciphers,
    and auth-method enumeration works."""

    def handle(self):
        try:
            self.request.settimeout(5)
            # Send identification string
            self.request.sendall(b"SSH-2.0-SleipnirMockSSH_Weak1.0\r\n")
            # Read client's KEXINIT
            data = self.request.recv(4096)
            if not data:
                return
            # Send KEXINIT with weak algorithms
            import struct
            cookie = b"\x00" * 16
            kex = b"diffie-hellman-group1-sha1"
            hostkey = b"ssh-rsa"
            ciphers = b"3des-cbc,arcfour"
            payload = (
                struct.pack(">I", 0) + cookie +
                struct.pack(">I", len(kex)) + kex +
                struct.pack(">I", len(hostkey)) + hostkey +
                struct.pack(">I", len(ciphers)) + ciphers +
                struct.pack(">I", len(ciphers)) + ciphers +
                struct.pack(">I", 8) + b"hmac-sha1" +
                struct.pack(">I", 5) + b"none" +
                struct.pack(">I", 0) + b"" +
                b"\x00" + struct.pack(">I", 0)
            )
            msg = bytes([20]) + struct.pack(">I", len(payload) + 32) + payload
            # Actually message type 20 = KEXINIT
            full = b"\x14" + struct.pack(">I", len(payload) + 32) + b"\x00" * 16 + payload
            self.request.sendall(full)
            time.sleep(0.3)
            # Keep connection open for auth-method enum
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                # Send USERAUTH_FAILURE to enumerate methods
                methods = b"publickey,password,keyboard-interactive"
                resp = (
                    b"\x00" +
                    bytes([51]) +  # SSH_MSG_USERAUTH_FAILURE
                    bytes([len(methods)]) +
                    methods +
                    b"\x00"
                )
                self.request.sendall(resp)
        except OSError:
            pass


class SshHardenedHandler(SshWeakCipherHandler):
    """SSH server that advertises only strong algorithms (negative stand)"""

    def handle(self):
        try:
            self.request.settimeout(5)
            self.request.sendall(b"SSH-2.0-SleipnirMockSSH_Strong1.0\r\n")
            data = self.request.recv(4096)
            if not data:
                return
            import struct
            cookie = b"\x00" * 16
            kex = b"curve25519-sha256,ecdh-sha2-nistp256"
            hostkey = b"ssh-ed25519,rsa-sha2-256"
            ciphers = b"chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
            payload = (
                struct.pack(">I", 0) + cookie +
                struct.pack(">I", len(kex)) + kex +
                struct.pack(">I", len(hostkey)) + hostkey +
                struct.pack(">I", len(ciphers)) + ciphers +
                struct.pack(">I", len(ciphers)) + ciphers +
                struct.pack(">I", 8) + b"hmac-sha1" +
                struct.pack(">I", 5) + b"none" +
                struct.pack(">I", 0) + b"" +
                b"\x00" + struct.pack(">I", 0)
            )
            full = b"\x14" + struct.pack(">I", len(payload) + 32) + b"\x00" * 16 + payload
            self.request.sendall(full)
            time.sleep(0.3)
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
        except OSError:
            pass


class MysqlDefaultCredsHandler(socketserver.StreamRequestHandler):
    """MySQL mock that allows root login with common default passwords."""

    DEFAULT_CREDS = {
        b"root": [b"root", b"", b"mysql", b"password", b"toor"],
    }

    def handle(self):
        try:
            self.request.settimeout(5)
            # Send handshake packet
            import struct
            salt = b"12345678"  # 8 bytes salt
            handshake = bytearray()
            handshake.append(0)  # protocol version
            handshake.extend(b"5.7.33-log\x00")  # server version
            handshake.extend(struct.pack("<I", 1))  # thread id
            handshake.extend(salt + b"\x00")
            handshake.extend(b"\x00\x00\x00\x00")  # scramblebles1 scramblebles
            self.request.sendall(bytes(handshake))
            # Read auth response
            data = self.request.recv(4096)
            if len(data) < 40:
                return
            # Parse username from auth response (simplified)
            if b"root" in data:
                for pw in self.DEFAULT_CREDS.get(b"root", []):
                    if pw in data:
                        # Auth success
                        ok = struct.pack("<I", 1) + b"\x00"
                        self.request.sendall(ok)
                        return
            # Auth failed
            err = struct.pack("<I", 1045) + b"Access denied for user 'root'@'localhost'"
            self.request.sendall(err)
        except OSError:
            pass


# ---------------------------------------------------------------------------

SERVICES = [
    ("ssh", 2201, SshHandler),
    ("ssh-weak", 2202, SshWeakCipherHandler),
    ("ssh-strong", 2203, SshHardenedHandler),
    ("ftp-vuln", 2101, FtpHandler),
    ("ftp-anon", 2102, FtpAnonHandler),
    ("http", 8080, LabHTTPRequestHandler, LabHTTPServer),
    ("https", 8443, ApacheDoubleTraversalHandler, LabHTTPServer),
    ("smtp-relay", 2501, SmtpRelayHandler),
    ("smtp-strict", 2502, SmtpStrictHandler),
    ("crashy-echo", 2503, EchoCrashHandler, CrashyTCPServer),
    ("redis", 6380, RedisLabHandler),
    ("redis-hard", 6381, RedisHardenedHandler),
    ("redis-pw", 6382, RedisPasswordHandler),
    ("docker-api", 2375, DockerApiHandler, LabHTTPServer),
    ("wordpress", 8081, WordPressHandler, LabHTTPServer),
    ("spa", 8082, SpaHandler, LabHTTPServer),
    ("vulnweb", 8083, VulnWebHandler, LabHTTPServer),
    # verification-stage negative stands: versions match the CVE records,
    # the active checks fail -> findings must stay "potential"
    ("apache-hardened", 8084, ApacheHardenedHandler, LabHTTPServer),
    ("php-hardened", 8085, PhpCgiHardenedHandler, LabHTTPServer),
    ("grafana-hardened", 8086, GrafanaHardenedHandler, LabHTTPServer),
    ("webmin-hardened", 8087, WebminHardenedHandler, LabHTTPServer),
    # verification-stage positive stands
    ("grafana-vuln", 8088, GrafanaHandler, LabHTTPServer),
    ("webmin-vuln", 8089, WebminHandler, LabHTTPServer),
    ("elasticsearch", 8090, ElasticsearchHandler, LabHTTPServer),
    ("es-hardened", 8091, ElasticsearchHardenedHandler, LabHTTPServer),
    ("bigip-vuln", 8092, BigIpHandler, LabHTTPServer),
    ("bigip-hardened", 8093, BigIpHardenedHandler, LabHTTPServer),
    ("jenkins-vuln", 8094, JenkinsHandler, LabHTTPServer),
    ("jenkins-hardened", 8095, JenkinsHardenedHandler, LabHTTPServer),
    ("authapp", 8096, AuthAppHandler, LabHTTPServer),
    ("mysql-defaults", 3307, MysqlDefaultCredsHandler),
]

class Ipv6TcpServer(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True


# TCP services re-bound on IPv6 loopback so `scan ::1` has something to find.
IPV6_SERVICES = [
    ("ssh-v6", 2201, SshHandler),
    ("http-v6", 8080, LabHTTPRequestHandler, Ipv6TcpServer),
]

UDP_SERVICES = [
    ("ssdp", 1900, UdpSsdpHandler),
    ("mdns", 5353, UdpMdnsHandler),
    ("memcached", 11211, UdpMemcachedHandler),
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

    for entry in IPV6_SERVICES:
        name, port, handler = entry[0], entry[1], entry[2]
        server_cls = entry[3] if len(entry) > 3 else Ipv6TcpServer
        srv = server_cls(("::1", port), handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        servers.append(srv)
        print(f"[mocklab] {name:12s} listening on [::1]:{port}")

    for entry in UDP_SERVICES:
        name, port, handler = entry[0], entry[1], entry[2]
        srv = UdpLabServer((HOST, port), handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        servers.append(srv)
        print(f"[mocklab] {name:12s} udp/{HOST}:{port}")

    print("[mocklab] ready. Ctrl+C to stop all services.")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[mocklab] shutting down")
        for srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    main()
