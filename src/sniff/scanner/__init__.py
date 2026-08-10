"""Public API for the sniff scanner core.

Importing from here gives you everything the CLI (and, later, the proxy)
needs without dragging in any transport-layer concerns.
"""

from sniff.scanner.models import Finding, ScanInput, ScanResult, Severity, Verdict
from sniff.scanner.rules import DEFAULT_RULES, Rule
from sniff.scanner.scanner import Scanner

__all__ = [
    "DEFAULT_RULES",
    "Finding",
    "Rule",
    "ScanInput",
    "ScanResult",
    "Scanner",
    "Severity",
    "Verdict",
]
