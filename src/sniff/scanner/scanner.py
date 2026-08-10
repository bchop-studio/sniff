"""The scanner: text in, ScanResult out.

The whole point of keeping this module thin and side-effect-free is that
later transports (proxy, library bindings) can call `Scanner.scan()`
without dragging in CLI code.
"""

from __future__ import annotations

import re

from sniff.scanner.models import (
    Finding,
    ScanInput,
    ScanResult,
    Severity,
    Verdict,
)
from sniff.scanner.rules import DEFAULT_RULES, Rule

_WS_RE = re.compile(r"\s+")


def _verdict_from_findings(findings: list[Finding]) -> Verdict:
    """Roll a list of findings up into a single verdict.

    - Any CRITICAL → DANGEROUS.
    - Any HIGH/MEDIUM → SUSPICIOUS.
    - LOW-only or no findings → CLEAN.
    """
    if any(f.severity is Severity.CRITICAL for f in findings):
        return Verdict.DANGEROUS
    if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings):
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _make_excerpt(content: str, start: int, end: int, window: int) -> str:
    """Carve a readable excerpt around a match, marked with `..` ellipses."""
    left = max(0, start - window)
    right = min(len(content), end + window)
    snippet = content[left:right].replace("\n", " ").replace("\r", " ")
    snippet = _WS_RE.sub(" ", snippet).strip()
    prefix = ".." if left > 0 else ""
    suffix = ".." if right < len(content) else ""
    return f"{prefix}{snippet}{suffix}"


class Scanner:
    """Runs a configurable rule set against arbitrary text.

    Construct once, call `.scan(...)` many times. The default rule set is
    `DEFAULT_RULES`; tests and the proxy can pass their own tuple.
    """

    def __init__(self, rules: tuple[Rule, ...] = DEFAULT_RULES) -> None:
        self._rules = rules

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def scan(self, scan_input: ScanInput) -> ScanResult:
        """Scan one piece of text. Never raises on bad input — bad bytes
        just yield a CLEAN result with zero findings."""
        content = scan_input.content
        findings: list[Finding] = []
        for rule in self._rules:
            for match in rule.pattern.finditer(content):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        excerpt=_make_excerpt(
                            content, match.start(), match.end(), rule.excerpt_window
                        ),
                        offset=match.start(),
                        rationale=rule.rationale,
                    )
                )
        verdict = _verdict_from_findings(findings)
        return ScanResult(
            verdict=verdict,
            findings=findings,
            bytes_scanned=len(content.encode("utf-8", errors="replace")),
            source=scan_input.source,
            source_kind=scan_input.source_kind,
        )
