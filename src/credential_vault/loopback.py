"""Short-lived localhost redirect transport; OAuth parsing stays with Authlib."""

from __future__ import annotations

import math
import socket
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, urlunsplit

from .errors import OAuthAuthenticationError


class LoopbackRedirect:
    """Bind only a loopback address for one explicitly requested login."""

    def __init__(self, uri: str, *, timeout: float) -> None:
        self.uri = uri
        self._timeout = timeout
        self._server = None
        self._response = None

    def __enter__(self):
        try:
            parts = urlsplit(self.uri)
            if (parts.scheme != "http" or parts.hostname not in {"localhost", "127.0.0.1", "::1"}
                    or parts.query or parts.fragment or parts.username or parts.password
                    or not math.isfinite(self._timeout) or self._timeout <= 0):
                raise ValueError
            owner = self

            class Handler(BaseHTTPRequestHandler):
                def setup(self):
                    self.request.settimeout(min(1.0, owner._timeout))
                    super().setup()

                def log_message(self, *args):
                    pass  # Request paths contain authorization codes.

                def do_GET(self):
                    request = urlsplit(self.path)
                    matched = request.path == parts.path and not request.scheme and not request.netloc
                    self.send_response(200 if matched else 404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Referrer-Policy", "no-referrer")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    if matched:
                        owner._response = owner.uri + ("?" + request.query if request.query else "")
                        self.wfile.write(b"Authorization response received. You may close this window.")

            class Server(HTTPServer):
                def handle_error(self, request, client_address):
                    pass  # Never print callback/request exception details.

            class IPv6Server(Server):
                address_family = socket.AF_INET6

            server_type = IPv6Server if parts.hostname == "::1" else Server
            address = "::1" if parts.hostname == "::1" else "127.0.0.1"
            self._server = server_type((address, parts.port if parts.port is not None else 80), Handler)
            # Bound request reads as well as the accept loop.
            self._server.socket.settimeout(min(1.0, self._timeout))
            host = "[::1]" if parts.hostname == "::1" else parts.hostname
            self.uri = urlunsplit(("http", f"{host}:{self._server.server_port}", parts.path, "", ""))
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise OAuthAuthenticationError("Unable to start OAuth loopback redirect") from None

    def authorize(self, url: str) -> str:
        if not webbrowser.open(url):
            raise OAuthAuthenticationError("Unable to open OAuth login browser")
        deadline = time.monotonic() + self._timeout
        while self._response is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OAuthAuthenticationError("OAuth login timed out")
            self._server.timeout = min(remaining, 0.5)
            self._server.handle_request()
        return self._response

    def __exit__(self, *args):
        if self._server is not None:
            self._server.server_close()
