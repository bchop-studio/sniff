"""Opt-in URL fetching for the sniff CLI, guarded against SSRF.

This module is the only place sniff touches the network. It is part of
the CLI transport layer; the scanner core stays pure and never imports
this.

Safety properties:

- Only ``http`` and ``https`` URLs. Everything else is rejected.
- No credentials (``user:pass@``) in URLs, including redirect targets.
- The destination host is resolved and every returned address must be a
  public, globally routable IP. Loopback, private, link-local (which
  covers the cloud metadata service at 169.254.169.254), multicast,
  reserved, and unspecified addresses are refused.
- Redirects are followed manually (never by urllib's handler) and every
  hop is re-validated against the same rules, so a public URL cannot
  bounce the scanner into an internal target.
- Responses are size-bounded; an over-limit body is a hard error, never
  a silent truncation (truncation could hide a payload past the cut).
- DNS rebinding defense: the pre-flight validation lookup is not
  trusted alone. The default transport resolves through
  `guarded_getaddrinfo`, which re-validates every connection-time DNS
  answer against the same block list, so a lookup that returns a
  private address at connect time is refused there too.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from email.message import Message
from typing import Protocol, cast

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB of text is far past any paste.
DEFAULT_MAX_REDIRECTS = 5
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# getaddrinfo's signature, minus what we don't use. Injectable so tests
# never touch real DNS.
Resolver = Callable[..., Sequence]


class FetchError(RuntimeError):
    """Any failure to safely retrieve a URL: policy refusal, DNS,
    network, HTTP status, redirect limit, or size limit."""


class RawResponse(Protocol):
    """The slice of urllib's response object fetch_url relies on."""

    status: int
    headers: Message

    def read(self, n: int = ...) -> bytes: ...

    def close(self) -> None: ...


class Opener(Protocol):
    """Injectable transport. The default wraps urllib with redirects
    disabled so every hop passes through validation here."""

    def open(self, url: str, *, timeout: float) -> RawResponse: ...


def fetch_url(
    url: str,
    *,
    opener: Opener | None = None,
    resolver: Resolver = socket.getaddrinfo,
    max_bytes: int = DEFAULT_MAX_BYTES,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> str:
    """Fetch `url` and return its body decoded as text.

    Raises FetchError on any policy refusal or retrieval failure. There
    is no fallback path: callers get text or an exception, never a
    guess.
    """
    if opener is None:
        opener = _UrllibOpener(resolver=resolver)

    current = url
    redirects_left = max_redirects
    while True:
        _validate_url(current, resolver)
        try:
            response = opener.open(current, timeout=timeout)
        except urllib.error.HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers else None
            if exc.code in _REDIRECT_STATUSES and location:
                if redirects_left <= 0:
                    raise FetchError(
                        f"too many redirects (limit {max_redirects}) fetching {url}"
                    ) from exc
                redirects_left -= 1
                current = urllib.parse.urljoin(current, location)
                continue
            raise FetchError(
                f"HTTP {exc.code} fetching {current}: {exc.reason or 'error'}"
            ) from exc
        except urllib.error.URLError as exc:
            raise FetchError(f"could not fetch {current}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise FetchError(f"timed out fetching {current}") from exc
        except OSError as exc:
            raise FetchError(f"could not fetch {current}: {exc}") from exc

        try:
            body = response.read(max_bytes + 1)
        except OSError as exc:
            raise FetchError(f"failed reading response from {current}: {exc}") from exc
        finally:
            response.close()

        if len(body) > max_bytes:
            raise FetchError(
                f"response from {current} is too large "
                f"(limit {max_bytes} bytes); refusing to scan a truncated body"
            )
        charset = _charset_from(response.headers) or "utf-8"
        return body.decode(charset, errors="replace")


# --- Validation ---------------------------------------------------------------


def _validate_url(url: str, resolver: Resolver) -> None:
    """Refuse anything that is not a plain public http(s) URL."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"could not parse URL {url!r}: {exc}") from exc

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        scheme = parts.scheme or "<none>"
        raise FetchError(
            f"unsupported URL scheme {scheme!r} in {url!r}; only http and https "
            "can be fetched"
        )
    if parts.username is not None or parts.password is not None:
        raise FetchError(
            f"credentials in URLs are not allowed ({url!r}); remove user:password@"
        )
    try:
        host = parts.hostname
        port = parts.port  # Accessing .port raises ValueError on a bad port.
    except ValueError as exc:
        raise FetchError(f"invalid port in URL {url!r}: {exc}") from exc
    if not host:
        raise FetchError(f"URL {url!r} has no host")

    _check_resolved_addresses(url, host, port, resolver)


def _check_resolved_addresses(
    url: str, host: str, port: int | None, resolver: Resolver
) -> None:
    effective_port = port or (443 if url.lower().startswith("https") else 80)
    try:
        infos = resolver(host, effective_port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError(f"could not resolve host {host!r}: {exc}") from exc

    raw_ips = {_sockaddr_ip(host, info) for info in infos}
    if not raw_ips:
        raise FetchError(f"host {host!r} resolved to no addresses")

    for raw in sorted(raw_ips):
        _assert_public_ip(host, raw)


def _sockaddr_ip(host: str, info: object) -> str:
    """Extract the IP string from a getaddrinfo record, or raise
    FetchError if the record is not the expected shape."""
    try:
        raw = info[4][0]  # type: ignore[index]
    except (IndexError, TypeError) as exc:
        raise FetchError(
            f"resolver returned a malformed record for {host!r}: {info!r}"
        ) from exc
    if not isinstance(raw, str):
        raise FetchError(
            f"resolver returned a malformed record for {host!r}: {info!r}"
        )
    return raw


def _assert_public_ip(host: str, raw: str) -> None:
    """Raise FetchError unless `raw` is a public, globally routable IP."""
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])  # strip IPv6 scope id
    except ValueError as exc:
        raise FetchError(
            f"host {host!r} resolved to an unparseable address {raw!r}"
        ) from exc
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    ):
        raise FetchError(
            f"host {host!r} resolves to blocked address {ip}; only public "
            "destinations can be fetched"
        )


def guarded_getaddrinfo(resolver: Resolver) -> Resolver:
    """Wrap a getaddrinfo-compatible resolver so every answer is
    re-validated against the SSRF block list.

    The default transport resolves through this wrapper at connection
    time. That closes the DNS-rebinding gap where the pre-flight check
    sees a public IP but the connection's own lookup returns a private
    one: the second answer is checked too, and blocked answers raise
    FetchError instead of being connected to.
    """

    def guarded(host: str, port: int, *args: object, **kwargs: object) -> Sequence:
        infos = resolver(host, port, *args, **kwargs)
        for info in infos:
            _assert_public_ip(host, _sockaddr_ip(host, info))
        return infos

    return guarded


def _charset_from(headers: object) -> str | None:
    get_charset = getattr(headers, "get_content_charset", None)
    if callable(get_charset):
        return cast("str | None", get_charset())
    return None


# --- Default transport ----------------------------------------------------------

# Serializes the temporary socket.getaddrinfo swap in _UrllibOpener.open.
_GUARD_LOCK = threading.Lock()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Disable urllib's automatic redirects. fetch_url re-validates every
    hop itself; urllib following blindly would bypass the SSRF guard."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _UrllibOpener:
    """Opener backed by urllib with redirects disabled and DNS guarded.

    During `open`, `socket.getaddrinfo` is temporarily replaced with a
    validating wrapper so the connection's own DNS answers pass the SSRF
    block list too (rebinding defense). This mutates a global, so all
    guarded opens are serialized through `_GUARD_LOCK`: no two fetches
    can interleave their patch windows, and the window is always
    restored on the way out. A long-lived multithreaded server should
    use a resolver-injected HTTP client instead of this module-level
    swap; for the single-shot CLI this is sufficient.
    """

    def __init__(self, resolver: Resolver = socket.getaddrinfo) -> None:
        self._opener = urllib.request.build_opener(_NoRedirectHandler())
        self._resolver = resolver

    def open(self, url: str, *, timeout: float) -> RawResponse:
        request = urllib.request.Request(
            url, headers={"User-Agent": "sniff/0.1 (+https://github.com/BeardedChop/sniff)"}
        )
        with _GUARD_LOCK:
            original = socket.getaddrinfo
            socket.getaddrinfo = guarded_getaddrinfo(self._resolver)  # type: ignore[assignment]
            try:
                return self._opener.open(request, timeout=timeout)
            finally:
                socket.getaddrinfo = original
