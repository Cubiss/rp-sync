from __future__ import annotations

import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .logging_utils import Logger
from .models import Protocol, RedirectConfig, ServiceConfig


@dataclass(frozen=True)
class RedirectTarget:
    canonical_host: str
    canonical_scheme: Protocol
    canonical_port: int


class _RedirectHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, handler_cls, backend: "RedirectBackend"):
        super().__init__(server_address, handler_cls)
        self.backend = backend


class _RedirectHandler(BaseHTTPRequestHandler):
    server: _RedirectHTTPServer

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self._handle()

    def _handle(self) -> None:
        host = (self.headers.get("Host") or "").strip()
        host = host.split(":", 1)[0].strip().lower()
        if not host:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        target = self.server.backend.get_target(host)
        if target is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        port_part = ""
        if (target.canonical_scheme == "http" and target.canonical_port != 80) or (
            target.canonical_scheme == "https" and target.canonical_port != 443
        ):
            port_part = f":{target.canonical_port}"
        location = f"{target.canonical_scheme}://{target.canonical_host}{port_part}{self.path}"

        self.send_response(308)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()


class RedirectBackend:
    def __init__(
        self,
        logger: Logger,
        cfg: RedirectConfig,
    ) -> None:
        self.logger = logger
        self.enabled = cfg.enabled
        self.bind_host = cfg.bind_host
        self.backend_host = cfg.backend_host or cfg.bind_host
        self.port = int(cfg.port)

        self._lock = threading.Lock()
        self._targets: dict[str, RedirectTarget] = {}
        self._server: Optional[_RedirectHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not self.enabled:
            return
        self._server = _RedirectHTTPServer((self.bind_host, self.port), _RedirectHandler, self)
        self._thread = threading.Thread(target=self._server.serve_forever, name="redirect", daemon=True)
        self._thread.start()
        self.logger.info(
            f"[redirect] enabled bind={self.bind_host} port={self.port} backend_host={self.backend_host}"
        )

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.shutdown()
        except Exception:
            pass
        try:
            self._server.server_close()
        except Exception:
            pass

    def update_from_services(self, services: list[ServiceConfig]) -> None:
        targets: dict[str, RedirectTarget] = {}
        for svc in services:
            canonical_host = svc.host.strip().lower()
            canonical_scheme: Protocol = "https" if svc.source_protocol == "https" else "http"
            canonical_port = int(svc.source_port)
            target = RedirectTarget(canonical_host, canonical_scheme, canonical_port)
            if canonical_host:
                targets[canonical_host] = target
            for a in svc.aliases:
                alias = a.strip().lower()
                if alias:
                    targets[alias] = target
        with self._lock:
            self._targets = targets

    def get_target(self, host: str) -> Optional[RedirectTarget]:
        h = host.strip().lower()
        with self._lock:
            return self._targets.get(h)

    def destination(self) -> tuple[str, int, Protocol]:
        return self.backend_host, self.port, "http"
