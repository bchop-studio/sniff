"""The scanner: text in, ScanResult out.

The whole point of keeping this module thin and side-effect-free is that
later transports (proxy, library bindings) can call `Scanner.scan()`
without dragging in CLI code.
"""

from __future__ import annotations

import re

from sniff.scanner.config import Config
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


def _apply_config(rules: tuple[Rule, ...], config: Config | None) -> tuple[Rule, ...]:
    """Apply Config overrides to the rule tuple.

    - Rules with `enabled: false` are dropped.
    - Rules with a `severity` override are rebuilt with the new severity
      (everything else — pattern, rationale, name — stays the same).

    A None config returns the rules unchanged.
    """
    if config is None:
        return rules

    overrides = config.rules
    out: list[Rule] = []
    for rule in rules:
        override = overrides.get(rule.rule_id)
        if override is not None and not override.enabled:
            continue
        if override is not None and override.severity is not None:
            out.append(
                Rule(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=override.severity,
                    pattern=rule.pattern,
                    rationale=rule.rationale,
                    excerpt_window=rule.excerpt_window,
                )
            )
        else:
            out.append(rule)
    return tuple(out)


class Scanner:
    """Runs a configurable rule set against arbitrary text.

    Construct once, call `.scan(...)` many times. The default rule set is
    `DEFAULT_RULES`; tests and the proxy can pass their own tuple, or
    pass a `Config` to apply enable/severity overrides on top.
    """

    def __init__(
        self,
        rules: tuple[Rule, ...] | None = None,
        config: Config | None = None,
    ) -> None:
        base_rules = rules if rules is not None else DEFAULT_RULES
        self._rules = _apply_config(base_rules, config)
        self._config = config

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @property
    def config(self) -> Config | None:
        return self._config

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
