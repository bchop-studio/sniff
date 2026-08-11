"""Injectable outbound transport seam for F2.1 forwarding.

This module defines the narrow boundary between the gateway's scan-then-
forward logic and any future real HTTP client.  The seam is **inert by
default**: ``InertTransport`` raises on every ``send`` call, so no
outbound connection can ever be made unless a caller explicitly wires
in a real transport.

Tests replace the transport with ``RecordingTransport`` to prove that
every failure path (blocked, suspicious, malformed, skipped, scanner
error) makes zero transport calls, and that only a fully scanned CLEAN
body reaches ``send``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


class TransportError(RuntimeError):
    """Raised when an outbound transport call fails or is not configured."""


@dataclass(frozen=True)
class ForwardRequest:
    """The exact payload handed to the transport after a CLEAN scan.

    ``messages`` is the validated, normalized message list that was
    scanned.  ``body_bytes`` is the serialized JSON body that will be
    sent upstream.  The two must represent the same content — tests
    assert that the scanned text appears in the serialized body.
    """

    messages: list[dict[str, object]]
    body_bytes: bytes
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ForwardResponse:
    """A bounded upstream response."""

    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class Transport(Protocol):
    """The injectable outbound transport seam.

    The gateway calls ``send`` only after a fully scanned CLEAN verdict.
    The default ``InertTransport`` raises on every call, so no outbound
    connection can ever happen unless a real transport is explicitly
    wired in.
    """

    def send(self, request: ForwardRequest) -> ForwardResponse: ...


class InertTransport:
    """The default transport: never sends, always raises.

    This is the safety guarantee.  The gateway starts with this
    transport unless a real one is explicitly injected, so no code path
    can reach the network without deliberate configuration.
    """

    def send(self, request: ForwardRequest) -> ForwardResponse:
        raise TransportError("transport not configured")


class RecordingTransport:
    """Test double that records every call without touching the network.

    ``call_count`` and ``calls`` let tests assert zero calls on failure
    paths and exactly one call on the clean path.  A configured
    ``response`` is returned on success; ``raise_on_send`` simulates a
    transport failure.
    """

    def __init__(
        self,
        *,
        response: ForwardResponse | None = None,
        raise_on_send: Exception | None = None,
    ) -> None:
        self._response = response
        self._raise = raise_on_send
        self.calls: list[ForwardRequest] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def send(self, request: ForwardRequest) -> ForwardResponse:
        self.calls.append(request)
        if self._raise is not None:
            raise self._raise
        if self._response is None:
            raise TransportError("no response configured")
        return self._response


__all__ = [
    "ForwardRequest",
    "ForwardResponse",
    "InertTransport",
    "RecordingTransport",
    "Transport",
    "TransportError",
]
