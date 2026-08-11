"""Authenticated, loopback-only screening gateway for sniff.

This is intentionally a screening service, not a forwarding proxy. It
accepts a bounded JSON message list, scans it, and returns a verdict. It
has no outbound HTTP client and never logs request bodies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseServer
from typing import Any, cast

from sniff.adapters import scan_messages
from sniff.scanner import Scanner

MAX_BODY_BYTES = 256 * 1024
MAX_MESSAGES = 100
MAX_MESSAGE_CONTENT_BYTES = 64 * 1024
MIN_TOKEN_LENGTH = 16
MAX_CONCURRENT_REQUESTS = 32
SOCKET_TIMEOUT_SECONDS = 5
SCAN_PATH = "/v1/scan/messages"


def _token_matches(presented: str, expected: str) -> bool:
    """Compare tokens without exposing validity through timing."""
    presented_bytes = hashlib.sha256(presented.encode("utf-8")).digest()
    expected_bytes = hashlib.sha256(expected.encode("utf-8")).digest()
    return hmac.compare_digest(presented_bytes, expected_bytes)


def _content_size(message: object) -> int:
    """Return the UTF-8 size of text content represented by a JSON message."""
    if not isinstance(message, dict):
        return 0
    content = message.get("content")
    if isinstance(content, str):
        return len(content.encode("utf-8", errors="replace"))
    if isinstance(content, list):
        return sum(
            len(part["text"].encode("utf-8", errors="replace"))
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        )
    return 0


def _findings_payload(result: Any) -> list[dict[str, object]]:
    return [
        {
            "message_index": index,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "severity": finding.severity.value,
        }
        for index, finding in result.findings
    ]


class GatewayServer(ThreadingHTTPServer):
    """Threaded screening server bound to the address supplied by the caller.

    The CLI constructs this only with ``127.0.0.1``. The class is public so
    tests and embedding applications can own its lifecycle explicitly.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], *, token: str) -> None:
        if server_address[0] not in {"127.0.0.1", "::1"}:
            raise ValueError("gateway must bind to loopback")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"gateway token must be at least {MIN_TOKEN_LENGTH} characters")
        super().__init__(server_address, _GatewayRequestHandler)
        self.token = token
        self.scanner = Scanner()
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.close_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _GatewayRequestHandler(BaseHTTPRequestHandler):
    """HTTP boundary for one authenticated scan request."""

    server: BaseServer

    def do_POST(self) -> None:
        server = cast(GatewayServer, self.server)
        if self.path != SCAN_PATH:
            self._write_error(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._authorized():
            self._write_error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return
        body = self._read_body()
        if body is None:
            return
        try:
            document = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid JSON")
            return
        if not isinstance(document, dict) or not isinstance(document.get("messages"), list):
            self._write_error(HTTPStatus.BAD_REQUEST, "messages must be a list")
            return

        messages = cast(list[object], document["messages"])
        if len(messages) > MAX_MESSAGES:
            self._write_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too many messages")
            return
        if any(_content_size(message) > MAX_MESSAGE_CONTENT_BYTES for message in messages):
            self._write_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "message content too large",
            )
            return

        screening_messages = [
            {"role": "user", "content": message.get("content")}
            if isinstance(message, dict)
            else message
            for message in messages
        ]
        result = scan_messages(server.scanner, screening_messages, roles={"user"})
        response = {
            "verdict": result.worst_verdict.value,
            "blocked": result.is_blocked,
            "scanned": result.scanned,
            "skipped": result.skipped,
            "findings": _findings_payload(result),
        }
        self._write_json(HTTPStatus.OK, response)

    def do_GET(self) -> None:
        if self.path == SCAN_PATH:
            self._write_error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
        else:
            self._write_error(HTTPStatus.NOT_FOUND, "not found")

    def do_PUT(self) -> None:
        self._write_error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

    do_PATCH = do_PUT
    do_DELETE = do_PUT

    def _authorized(self) -> bool:
        server = cast(GatewayServer, self.server)
        header = self.headers.get("Authorization", "")
        scheme, separator, presented = header.partition(" ")
        return (
            scheme.lower() == "bearer"
            and separator == " "
            and bool(presented)
            and _token_matches(presented, server.token)
        )

    def _read_body(self) -> bytes | None:
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
            return None
        if content_length < 0:
            self._write_error(HTTPStatus.LENGTH_REQUIRED, "Content-Length required")
            return None
        if content_length > MAX_BODY_BYTES:
            self._write_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body too large")
            return None
        return self.rfile.read(content_length)

    def _write_error(self, status: HTTPStatus, message: str) -> None:
        self._write_json(status, {"error": message})

    def _write_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        """Do not log paths, headers, or request-derived values."""
        return
