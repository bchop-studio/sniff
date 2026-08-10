"""Tests for the SSRF-guarded URL fetcher used by the CLI's URL mode."""

from __future__ import annotations

import email.message
import socket
import urllib.error
from collections.abc import Callable

import pytest

from sniff.cli.url_fetch import (
    DEFAULT_TIMEOUT_SECONDS,
    FetchError,
    fetch_url,
    guarded_getaddrinfo,
)

PUBLIC_IP = "93.184.216.34"  # example.com's well-known public address
PRIVATE_IP = "10.0.0.8"
LOOPBACK_IP = "127.0.0.1"
METADATA_IP = "169.254.169.254"  # cloud metadata service (link-local)


def _resolver_for(ip: str) -> Callable:
    """A getaddrinfo stand-in that always resolves to `ip`."""

    def resolve(host: str, port: int, *, type: int = 0) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    return resolve


class FakeResponse:
    def __init__(
        self, body: bytes = b"", status: int = 200, content_type: str = "text/plain"
    ) -> None:
        self._body = body
        self.status = status
        self.headers = email.message.Message()
        self.headers["Content-Type"] = content_type

    def read(self, n: int = -1) -> bytes:
        return self._body if n < 0 else self._body[:n]

    def close(self) -> None:
        pass


def _http_error(url: str, code: int, location: str | None = None) -> urllib.error.HTTPError:
    headers = email.message.Message()
    if location is not None:
        headers["Location"] = location
    return urllib.error.HTTPError(url, code, "status", headers, None)


class FakeOpener:
    """Serves queued outcomes keyed by URL. An outcome is a FakeResponse or
    an exception instance to raise."""

    def __init__(self, outcomes: dict[str, object]) -> None:
        self.outcomes = outcomes
        self.requested: list[str] = []

    def open(self, url: str, *, timeout: float) -> FakeResponse:
        self.requested.append(url)
        outcome = self.outcomes[url]
        if isinstance(outcome, Exception):
            raise outcome
        assert isinstance(outcome, FakeResponse)
        return outcome


def _fetch(url: str, opener: FakeOpener, ip: str = PUBLIC_IP, **kwargs) -> str:
    return fetch_url(url, opener=opener, resolver=_resolver_for(ip), **kwargs)


# --- Happy path -------------------------------------------------------------


def test_fetches_and_decodes_text() -> None:
    opener = FakeOpener({"https://example.com/": FakeResponse(b"hello world")})
    text = _fetch("https://example.com/", opener)
    assert text == "hello world"
    assert opener.requested == ["https://example.com/"]


def test_follows_redirect_to_public_target() -> None:
    opener = FakeOpener(
        {
            "https://example.com/a": _http_error(
                "https://example.com/a", 302, location="https://example.com/b"
            ),
            "https://example.com/b": FakeResponse(b"redirected"),
        }
    )
    assert _fetch("https://example.com/a", opener) == "redirected"


def test_relative_redirect_location_is_resolved() -> None:
    opener = FakeOpener(
        {
            "https://example.com/a": _http_error("https://example.com/a", 301, location="/b"),
            "https://example.com/b": FakeResponse(b"relative ok"),
        }
    )
    assert _fetch("https://example.com/a", opener) == "relative ok"


# --- Scheme, credentials, ports ----------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "gopher://example.com/",
        "https:///path-only",
    ],
)
def test_rejects_non_http_schemes_and_hostless_urls(url: str) -> None:
    opener = FakeOpener({})
    with pytest.raises(FetchError):
        _fetch(url, opener)
    assert opener.requested == []


def test_rejects_credentials_in_url() -> None:
    opener = FakeOpener({})
    with pytest.raises(FetchError, match="credential"):
        _fetch("https://user:pass@example.com/", opener)
    assert opener.requested == []


def test_rejects_invalid_port() -> None:
    opener = FakeOpener({})
    with pytest.raises(FetchError):
        _fetch("https://example.com:99999/", opener)


# --- SSRF guard ---------------------------------------------------------------


@pytest.mark.parametrize("ip", [LOOPBACK_IP, PRIVATE_IP, METADATA_IP, "192.168.1.1", "::1"])
def test_blocks_private_loopback_and_metadata_destinations(ip: str) -> None:
    opener = FakeOpener({"https://internal.local/": FakeResponse(b"secret")})
    with pytest.raises(FetchError, match="blocked"):
        _fetch("https://internal.local/", opener, ip=ip)
    assert opener.requested == []


def test_blocks_redirect_to_private_target() -> None:
    opener = FakeOpener(
        {
            "https://example.com/a": _http_error(
                "https://example.com/a", 302, location="https://internal.local/"
            ),
        }
    )
    # First hop resolves public, second hop resolves private.
    calls = {"n": 0}

    def resolver(host: str, port: int, *, type: int = 0) -> list:
        calls["n"] += 1
        ip = PUBLIC_IP if calls["n"] == 1 else PRIVATE_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    with pytest.raises(FetchError, match="blocked"):
        fetch_url("https://example.com/a", opener=opener, resolver=resolver)


def test_blocks_url_with_redirect_to_credentials() -> None:
    opener = FakeOpener(
        {
            "https://example.com/a": _http_error(
                "https://example.com/a", 302, location="https://user:pw@example.com/b"
            ),
        }
    )
    with pytest.raises(FetchError, match="credential"):
        _fetch("https://example.com/a", opener)


# --- Bounds and error surfacing -------------------------------------------------


def test_too_many_redirects_is_an_error() -> None:
    outcomes: dict[str, object] = {}
    for i in range(10):
        outcomes[f"https://example.com/{i}"] = _http_error(
            f"https://example.com/{i}", 302, location=f"https://example.com/{i + 1}"
        )
    opener = FakeOpener(outcomes)
    with pytest.raises(FetchError, match="redirect"):
        _fetch("https://example.com/0", opener)


def test_oversized_body_is_an_error_not_truncation() -> None:
    opener = FakeOpener({"https://example.com/": FakeResponse(b"x" * 2048)})
    with pytest.raises(FetchError, match="too large"):
        _fetch("https://example.com/", opener, max_bytes=1024)


def test_http_error_status_is_clear_error() -> None:
    opener = FakeOpener(
        {"https://example.com/missing": _http_error("https://example.com/missing", 404)}
    )
    with pytest.raises(FetchError, match="404"):
        _fetch("https://example.com/missing", opener)


def test_network_failure_is_clear_error() -> None:
    opener = FakeOpener(
        {"https://example.com/": urllib.error.URLError("connection refused")}
    )
    with pytest.raises(FetchError, match=r"example\.com"):
        _fetch("https://example.com/", opener)


def test_timeout_is_clear_error() -> None:
    opener = FakeOpener({"https://example.com/": TimeoutError("timed out")})
    with pytest.raises(FetchError, match="timed out"):
        _fetch("https://example.com/", opener)


def test_dns_failure_is_clear_error() -> None:
    def bad_resolver(host: str, port: int, *, type: int = 0) -> list:
        raise socket.gaierror(-2, "Name or service not known")

    opener = FakeOpener({})
    with pytest.raises(FetchError, match="resolve"):
        fetch_url("https://no-such-host.invalid/", opener=opener, resolver=bad_resolver)


# --- Review follow-ups: connection-time DNS guard, malformed data, bounds ------


class RecordingOpener:
    def __init__(self, body: bytes = b"ok") -> None:
        self.timeouts: list[float] = []
        self._body = body

    def open(self, url: str, *, timeout: float) -> FakeResponse:
        self.timeouts.append(timeout)
        return FakeResponse(self._body)


def test_default_timeout_is_forwarded_to_transport() -> None:
    opener = RecordingOpener()
    fetch_url(
        "https://example.com/", opener=opener, resolver=_resolver_for(PUBLIC_IP)
    )
    assert opener.timeouts == [DEFAULT_TIMEOUT_SECONDS]


def test_explicit_timeout_is_forwarded() -> None:
    opener = RecordingOpener()
    fetch_url(
        "https://example.com/",
        opener=opener,
        resolver=_resolver_for(PUBLIC_IP),
        timeout=2.5,
    )
    assert opener.timeouts == [2.5]


@pytest.mark.parametrize(
    "ip",
    ["224.0.0.1", "240.0.0.1", "100.64.0.1", "0.0.0.0", "fe80::1", "ff02::1"],
)
def test_multicast_reserved_cgnat_and_unspecified_are_blocked(ip: str) -> None:
    opener = FakeOpener({"https://example.com/": FakeResponse(b"x")})
    with pytest.raises(FetchError, match="blocked"):
        _fetch("https://example.com/", opener, ip=ip)
    assert opener.requested == []


def test_malformed_resolver_address_is_fetch_error_not_value_error() -> None:
    def garbage_resolver(host: str, port: int, *, type: int = 0) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", port))]

    opener = FakeOpener({})
    with pytest.raises(FetchError):
        fetch_url(
            "https://example.com/", opener=opener, resolver=garbage_resolver
        )
    assert opener.requested == []


def test_connection_time_dns_guard_reblocks_a_rebound_private_answer() -> None:
    """If the transport's own DNS lookup answers with a private IP (DNS
    rebinding), the connection-time guard must refuse it even though the
    pre-flight validation saw a public address."""
    guarded = guarded_getaddrinfo(_resolver_for(PRIVATE_IP))
    with pytest.raises(FetchError, match="blocked"):
        guarded("example.com", 443, type=socket.SOCK_STREAM)


def test_connection_time_dns_guard_passes_public_answers() -> None:
    guarded = guarded_getaddrinfo(_resolver_for(PUBLIC_IP))
    infos = guarded("example.com", 443, type=socket.SOCK_STREAM)
    assert infos[0][4][0] == PUBLIC_IP


def test_connection_time_dns_guard_rejects_malformed_addresses() -> None:
    def garbage_resolver(host: str, port: int, **kwargs: object) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("junk", port))]

    guarded = guarded_getaddrinfo(garbage_resolver)
    with pytest.raises(FetchError):
        guarded("example.com", 443)


def test_preflight_rejects_malformed_resolver_records() -> None:
    bad_records: list[list] = [
        [],
        [(socket.AF_INET, socket.SOCK_STREAM, 6)],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", None)],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (None, 443))],
    ]
    for record in bad_records:
        def bad_resolver(host: str, port: int, _r: list = record, **kw: object) -> list:
            return _r

        opener = FakeOpener({})
        with pytest.raises(FetchError):
            fetch_url("https://example.com/", opener=opener, resolver=bad_resolver)
        assert opener.requested == []


def test_connection_time_guard_rejects_malformed_records() -> None:
    def bad_resolver(host: str, port: int, **kw: object) -> list:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", None)]

    with pytest.raises(FetchError):
        guarded_getaddrinfo(bad_resolver)("example.com", 443)
