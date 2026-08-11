"""CLI entry point for the local sniff screening gateway."""

from __future__ import annotations

import argparse
import os
import sys

from sniff.gateway.server import MIN_TOKEN_LENGTH, GatewayServer

_TOKEN_ENV = "SNIFF_GATEWAY_TOKEN"


def main() -> None:
    """Start the authenticated loopback-only screening gateway."""
    parser = argparse.ArgumentParser(
        prog="sniff-gateway",
        description="Start sniff's local, non-forwarding message screening gateway.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Loopback TCP port (default: 8765).",
    )
    args = parser.parse_args()

    token = os.environ.get(_TOKEN_ENV, "")
    if len(token) < MIN_TOKEN_LENGTH:
        print(
            f"error: {_TOKEN_ENV} must be set to at least {MIN_TOKEN_LENGTH} characters",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not 1 <= args.port <= 65535:
        print("error: --port must be between 1 and 65535", file=sys.stderr)
        raise SystemExit(2)

    server = GatewayServer(("127.0.0.1", args.port), token=token)
    print(f"sniff-gateway listening on 127.0.0.1:{args.port}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
