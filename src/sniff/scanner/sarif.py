"""SARIF 2.1.0 export for sniff scan results.

SARIF (Static Analysis Results Interchange Format) is the JSON standard
CI systems — GitHub code scanning, Azure DevOps, VS Code's SARIF viewer —
read to display findings. This module is a pure function layer: a
ScanResult plus the rule set that produced it in, a JSON-ready dict out.
No I/O, no CLI imports, so any future transport (proxy, library) gets
SARIF for free.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from typing import Any

from sniff.scanner.models import Finding, ScanResult, Severity
from sniff.scanner.rules import Rule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)

# sniff is a scanner, so findings are security-relevant by definition;
# map sniff severities onto SARIF's note/warning/error levels.
_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "warning",
    Severity.CRITICAL: "error",
}


def _rule_metadata(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.rule_id,
        "name": rule.name,
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.rationale},
        "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[rule.severity]},
        "properties": {
            "severity": rule.severity.value,
            "tags": ["prompt-injection", "security"],
        },
    }


def _result_entry(finding: Finding, source_uri: str) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": f"{finding.rule_name}: {finding.excerpt}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_uri},
                    "region": {"charOffset": finding.offset},
                }
            }
        ],
    }


def result_to_sarif(result: ScanResult, rules: tuple[Rule, ...]) -> dict[str, Any]:
    """Convert one ScanResult into a SARIF 2.1.0 document.

    `rules` is the rule set that produced the result (usually
    `DEFAULT_RULES`, or the scanner's effective rules after config
    overrides) so the `tool.driver.rules` metadata matches what was
    actually run. Returns a plain dict ready for `json.dumps`.
    """
    source_uri = result.source or "stdin"
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sniff",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/BeardedChop/sniff",
                        "rules": [_rule_metadata(r) for r in rules],
                    }
                },
                "results": [_result_entry(f, source_uri) for f in result.findings],
            }
        ],
    }
