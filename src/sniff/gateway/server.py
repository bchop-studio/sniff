"""Authenticated, loopback-only screening gateway for sniff.

This is a screening service with an injectable outbound transport seam.
The default transport (InertTransport) never sends anything.  When a
real transport is injected, the ``/v1/forward/messages`` endpoint scans
the full request first, and only a completely parsed, fully scanned
CLEAN body reaches the transport.  Every failure path — blocked,
suspicious, malformed, skipped, scanner-error — makes zero transport
calls.
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
from sniff.gateway.transport import (
    ForwardRequest,
    ForwardResponse,
    InertTransport,
    Transport,
    TransportError,
)
from sniff.scanner import Scanner
from sniff.scanner.models import Verdict

MAX_BODY_BYTES = 256 * 1024
MAX_MESSAGES = 100
MAX_MESSAGE_CONTENT_BYTES = 64 * 1024
MIN_TOKEN_LENGTH = 16
MAX_CONCURRENT_REQUESTS = 32
SOCKET_TIMEOUT_SECONDS = 5
SCAN_PATH = "/v1/scan/messages"
FORWARD_PATH = "/v1/forward/messages"
SUPPORTED_VERSION = 1
ALLOWED_ROLES: frozenset[str] = frozenset({"user", "tool", "function"})

# Fields allowed in each message of the forwarding schema.
_ALLOWED_MESSAGE_FIELDS: frozenset[str] = frozenset({"role", "content"})

# Fields allowed in each text part of a multimodal content list.
_ALLOWED_PART_FIELDS: frozenset[str] = frozenset({"type", "text"})


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate object keys before schema validation can collapse them."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


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

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        token: str,
        transport: Transport | None = None,
        upstream_credential: str | None = None,
    ) -> None:
        if server_address[0] not in {"127.0.0.1", "::1"}:
            raise ValueError("gateway must bind to loopback")
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"gateway token must be at least {MIN_TOKEN_LENGTH} characters")
        super().__init__(server_address, _GatewayRequestHandler)
        self.token = token
        self.scanner = Scanner()
        self.transport: Transport = transport if transport is not None else InertTransport()
        self.upstream_credential = upstream_credential
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            # Gate 21: return a stable overload response instead of
            # silently dropping the connection.
            try:
                payload = b'{"error":"overloaded"}'
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload
                )
            except OSError:
                pass
            self.close_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _GatewayRequestHandler(BaseHTTPRequestHandler):
    """HTTP boundary for one authenticated scan or forward request."""

    server: BaseServer

    # --- Routing --------------------------------------------------------

    def do_POST(self) -> None:
        if self.path == SCAN_PATH:
            self._handle_scan()
        elif self.path == FORWARD_PATH:
            self._handle_forward()
        else:
            self._write_error(HTTPStatus.NOT_FOUND, "not found")

    def do_GET(self) -> None:
        if self.path in {SCAN_PATH, FORWARD_PATH}:
            self._write_error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")
        else:
            self._write_error(HTTPStatus.NOT_FOUND, "not found")

    def do_PUT(self) -> None:
        self._write_error(HTTPStatus.METHOD_NOT_ALLOWED, "method not allowed")

    do_PATCH = do_PUT
    do_DELETE = do_PUT

    # --- Scan endpoint --------------------------------------------------

    def _handle_scan(self) -> None:
        server = cast(GatewayServer, self.server)
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

    # --- Forward endpoint --------------------------------------------------

    def _handle_forward(self) -> None:
        server = cast(GatewayServer, self.server)

        # Gate 7: auth failures never reach the transport.
        if not self._authorized():
            self._write_error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return

        # Concurrency is already bounded by process_request's semaphore.
        self._do_forward(server)

    def _do_forward(self, server: GatewayServer) -> None:
        # Gate 1: no live forwarding unless a real transport is wired.
        if isinstance(server.transport, InertTransport):
            self._write_error(HTTPStatus.NOT_IMPLEMENTED, "forwarding not enabled")
            return

        # Gate 10: reject duplicate Content-Length.
        if self._has_duplicate_content_length():
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid Content-Length")
            return
        if self.headers.get_all("Transfer-Encoding"):
            self._write_error(HTTPStatus.BAD_REQUEST, "unsupported Transfer-Encoding")
            return

        body = self._read_body()
        if body is None:
            return

        # Gate 12: parse and validate before any scan or transport call.
        try:
            document = json.loads(body, object_pairs_hook=_reject_duplicate_json_keys)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError):
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid JSON")
            return

        messages = self._validate_forward_document(document)
        if messages is None:
            return  # _validate already wrote the error

        # Gate 15: scan every message individually plus the aggregate.
        scan_result = self._scan_for_forward(server, messages)
        if scan_result is None:
            return  # error already written

        worst_verdict, findings = scan_result

        # Gates 13, 15: only CLEAN reaches the transport.
        if worst_verdict is not Verdict.CLEAN:
            self._write_json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "blocked",
                    "verdict": worst_verdict.value,
                    "findings": findings,
                },
            )
            return

        # Gate 15: the normalized values scanned are exactly those serialized.
        body_bytes = json.dumps(
            {"version": SUPPORTED_VERSION, "messages": messages},
            separators=(",", ":"),
        ).encode("utf-8")

        # Gate 8: gateway token is never in the outbound request.
        # Gate 9: upstream credential is injected only here.
        # Gate 11: Accept-Encoding: identity, gateway-generated Host and Content-Length.
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body_bytes)),
            "Accept-Encoding": "identity",
            "Host": "upstream",
        }
        if server.upstream_credential:
            headers["Authorization"] = f"Bearer {server.upstream_credential}"

        forward_request = ForwardRequest(
            messages=messages,
            body_bytes=body_bytes,
            headers=headers,
        )

        # Gate 24: no retry — exactly one send call.
        try:
            response = server.transport.send(forward_request)
        except TransportError:
            # Gate 20: no raw exception text leaks to the client.
            self._write_error(HTTPStatus.BAD_GATEWAY, "upstream error")
            return
        except Exception:
            self._write_error(HTTPStatus.BAD_GATEWAY, "upstream error")
            return

        # Gate 20: upstream credential must not appear in the response.
        self._write_forward_response(response, server)

    def _write_forward_response(self, response: ForwardResponse, server: GatewayServer) -> None:
        """Write the upstream response to the client, stripping credentials."""
        # Parse the upstream body so we can return a bounded JSON response.
        try:
            upstream_body = json.loads(response.body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write_error(HTTPStatus.BAD_GATEWAY, "upstream error")
            return

        # Gate 20: ensure no credential leaks in the response body.
        encoded = json.dumps(upstream_body)
        if server.upstream_credential and server.upstream_credential in encoded:
            self._write_error(HTTPStatus.BAD_GATEWAY, "upstream error")
            return

        self._write_json(HTTPStatus.OK, upstream_body)

    def _scan_for_forward(
        self,
        server: GatewayServer,
        messages: list[dict[str, object]],
    ) -> tuple[Verdict, list[dict[str, object]]] | None:
        """Scan every message individually and as an aggregate.

        Returns (worst_verdict, findings) or None if an error was written.
        """
        from sniff.scanner.models import ScanInput

        # Build screening messages: treat all as untrusted "user" role.
        screening_messages: list[dict[str, object]] = []
        all_texts: list[str] = []

        for msg in messages:
            content = msg["content"]
            if isinstance(content, str):
                screening_messages.append({"role": "user", "content": content})
                all_texts.append(content)
            elif isinstance(content, list):
                parts = [
                    part["text"]
                    for part in content
                    if isinstance(part, dict) and isinstance(part.get("text"), str)
                ]
                text = " ".join(parts)
                screening_messages.append({"role": "user", "content": text})
                all_texts.append(text)
            else:
                self._write_error(HTTPStatus.BAD_REQUEST, "invalid message content")
                return None

        # Individual message scan.
        result = scan_messages(server.scanner, screening_messages, roles={"user"})

        # Gate 15: aggregate scan catches injection split across messages.
        aggregate_text = "\n".join(all_texts)
        aggregate_result = server.scanner.scan(
            ScanInput(content=aggregate_text, source="aggregate", source_kind="text")
        )

        # Roll up the worst verdict.
        worst = result.worst_verdict
        if aggregate_result.verdict is Verdict.DANGEROUS:
            worst = Verdict.DANGEROUS
        elif aggregate_result.verdict is Verdict.SUSPICIOUS and worst is Verdict.CLEAN:
            worst = Verdict.SUSPICIOUS

        findings = _findings_payload(result)
        if aggregate_result.findings:
            findings.extend(
                {
                    "message_index": -1,
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                }
                for f in aggregate_result.findings
            )

        return worst, findings

    def _validate_forward_document(
        self, document: object
    ) -> list[dict[str, object]] | None:
        """Validate the forwarding schema. Returns messages or None (error written).

        Gate 12: reject invalid JSON structure, unknown fields, unsupported
        roles, non-text content, empty messages, and missing version.
        """
        if not isinstance(document, dict):
            self._write_error(HTTPStatus.BAD_REQUEST, "invalid request body")
            return None

        # Reject unknown top-level fields (gate 12, gate 1: no caller-controlled destination).
        allowed_top: frozenset[str] = frozenset({"version", "messages"})
        extra = set(document.keys()) - allowed_top
        if extra:
            self._write_error(HTTPStatus.BAD_REQUEST, "unsupported field in request body")
            return None

        # Version must be exactly the supported version.
        version = document.get("version")
        if version != SUPPORTED_VERSION:
            self._write_error(HTTPStatus.BAD_REQUEST, "unsupported or missing version")
            return None

        raw_messages = document.get("messages")
        if not isinstance(raw_messages, list):
            self._write_error(HTTPStatus.BAD_REQUEST, "messages must be a list")
            return None

        if len(raw_messages) == 0:
            self._write_error(HTTPStatus.BAD_REQUEST, "messages must not be empty")
            return None

        if len(raw_messages) > MAX_MESSAGES:
            self._write_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too many messages")
            return None

        messages: list[dict[str, object]] = []
        for raw in raw_messages:
            if not isinstance(raw, dict):
                self._write_error(HTTPStatus.BAD_REQUEST, "invalid message")
                return None

            # Reject unknown message fields.
            extra_fields = set(raw.keys()) - _ALLOWED_MESSAGE_FIELDS
            if extra_fields:
                self._write_error(HTTPStatus.BAD_REQUEST, "unsupported field in message")
                return None

            role = raw.get("role")
            if not isinstance(role, str) or role not in ALLOWED_ROLES:
                self._write_error(HTTPStatus.BAD_REQUEST, "unsupported role")
                return None

            content = raw.get("content")
            if isinstance(content, str):
                if len(content.encode("utf-8", errors="replace")) > MAX_MESSAGE_CONTENT_BYTES:
                    self._write_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "message content too large")
                    return None
                messages.append({"role": role, "content": content})
            elif isinstance(content, list):
                # Validate each part.
                validated_parts: list[dict[str, str]] = []
                for part in content:
                    if not isinstance(part, dict):
                        self._write_error(HTTPStatus.BAD_REQUEST, "invalid content part")
                        return None
                    extra_part = set(part.keys()) - _ALLOWED_PART_FIELDS
                    if extra_part:
                        self._write_error(HTTPStatus.BAD_REQUEST, "unsupported field in content part")
                        return None
                    if part.get("type") != "text" or not isinstance(part.get("text"), str):
                        self._write_error(HTTPStatus.BAD_REQUEST, "only text content parts are supported")
                        return None
                    validated_parts.append({"type": "text", "text": part["text"]})
                if not validated_parts:
                    self._write_error(HTTPStatus.BAD_REQUEST, "empty content list")
                    return None
                messages.append({"role": role, "content": validated_parts})
            else:
                self._write_error(HTTPStatus.BAD_REQUEST, "invalid message content")
                return None

        return messages

    # --- Auth and body helpers --------------------------------------------

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

    def _has_duplicate_content_length(self) -> bool:
        """Gate 10: detect duplicate Content-Length headers."""
        headers = self.headers.get_all("Content-Length")  # type: ignore[attr-defined]
        if headers is None:
            return False
        return len(headers) > 1

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
