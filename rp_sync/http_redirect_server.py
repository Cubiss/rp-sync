from __future__ import annotations

import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlsplit

from .logging_utils import Logger
from .models import HttpRedirectConfig


def _pick_host(handler: BaseHTTPRequestHandler, canonical_host: Optional[str]) -> str:
    if canonical_host:
        return canonical_host

    # Prefer proxy-provided host header
    xf_host = handler.headers.get("X-Forwarded-Host")
    if xf_host:
        # In case of a comma-separated list, use the first
        return xf_host.split(",")[0].strip()

    host = handler.headers.get("Host", "")
    host = host.strip()
    if not host:
        return "localhost"

    # Strip :80 if present
    if host.endswith(":80"):
        host = host[:-3]
    return host


class _RedirectHandler(BaseHTTPRequestHandler):
    # These are set by the factory in start_redirect_server()
    redirect_code: int = 308
    canonical_host: Optional[str] = None

    def _send_redirect(self) -> None:
        host = _pick_host(self, self.canonical_host)

        # Preserve path + query
        # self.path already includes query string if present
        location = f"https://{host}{self.path}"

        self.send_response(self.redirect_code)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._send_redirect()

    def do_HEAD(self) -> None:  # noqa: N802
        self._send_redirect()

    def do_POST(self) -> None:  # noqa: N802
        self._send_redirect()

    def do_PUT(self) -> None:  # noqa: N802
        self._send_redirect()

    def do_DELETE(self) -> None:  # noqa: N802
        self._send_redirect()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_redirect()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Keep output quiet; rp-sync has its own logging.
        return


@dataclass
class RedirectServer:
    server: ThreadingHTTPServer
    thread: threading.Thread

    def stop(self, logger: Logger) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        finally:
            self.thread.join(timeout=5)
            logger.info("[http_redirect] Redirect server stopped")


def start_redirect_server(logger: Logger, cfg: HttpRedirectConfig) -> RedirectServer:
    """Start a tiny HTTP server that always redirects to HTTPS.

    This is meant to be used as a backend for DSM Reverse Proxy.
    """

    listen_host = cfg.builtin_backend.listen_host
    listen_port = cfg.builtin_backend.listen_port
    code = int(cfg.builtin_backend.code)

    # Validate backend_url matches our listener reasonably (best effort)
    try:
        p = urlsplit(cfg.backend_url)
        if p.scheme and p.scheme.lower() != "http":
            logger.warning(
                f"[http_redirect] backend_url is '{cfg.backend_url}', but builtin backend is HTTP"
            )
    except Exception:
        pass

    # Create a handler subclass with embedded config
    class Handler(_RedirectHandler):
        redirect_code = code
        canonical_host = cfg.canonical_host

    httpd = ThreadingHTTPServer((listen_host, listen_port), Handler)

    t = threading.Thread(target=httpd.serve_forever, name="rp-sync-http-redirect", daemon=True)
    t.start()

    logger.info(
        f"[http_redirect] Builtin redirect server listening on {listen_host}:{listen_port} "
        f"(code {code})"
    )

    return RedirectServer(server=httpd, thread=t)
