"""Public API for the sniff scanner core.

Importing from here gives you everything the CLI (and, later, the proxy)
needs without dragging in any transport-layer concerns.
"""

from sniff.scanner.config import Config, ConfigError, RuleOverride, load_config
from sniff.scanner.models import Finding, ScanInput, ScanResult, Severity, Verdict
from sniff.scanner.rules import DEFAULT_RULES, Rule
from sniff.scanner.scanner import Scanner

__all__ = [
    "DEFAULT_RULES",
    "Config",
    "ConfigError",
    "Finding",
    "Rule",
    "RuleOverride",
    "ScanInput",
    "ScanResult",
    "Scanner",
    "Severity",
    "Verdict",
    "load_config",
]
