"""Framework adapters: scan agent inputs at the message boundary.

`scan_messages` is the framework-agnostic entry point. A per-framework
integration is just a thin wrapper that hands its message list here.
"""

from sniff.adapters.messages import (
    DEFAULT_SCANNED_ROLES,
    MessageScanResult,
    scan_messages,
)

__all__ = [
    "DEFAULT_SCANNED_ROLES",
    "MessageScanResult",
    "scan_messages",
]
