"""Core data models for sniff.

Kept in their own module so the proxy can import them without pulling in
the rule implementations.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    """How worried to be about a single finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Top-level outcome of a scan.

    - CLEAN: nothing flagged. Safe to pass through.
    - SUSPICIOUS: some signals worth a human eye. Pass with caution.
    - DANGEROUS: high-confidence injection. Block by default.
    """

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


SourceKind = Literal["text", "file", "url"]


class ScanInput(BaseModel):
    """A unit of text handed to the scanner.

    `source` is opaque to the scanner — it is for the caller's bookkeeping
    (filename, URL, prompt ID). The scanner only inspects `content`.
    """

    content: str = Field(min_length=0)
    source: str = ""
    source_kind: SourceKind = "text"

    @field_validator("content")
    @classmethod
    def _strip_bom(cls, v: str) -> str:
        return v.lstrip("\ufeff")


class Finding(BaseModel):
    """One rule hit inside scanned content."""

    rule_id: str
    rule_name: str
    severity: Severity
    excerpt: str = Field(max_length=240)
    offset: int = Field(ge=0)
    rationale: str


class ScanResult(BaseModel):
    """Verdict + every finding, in scan order."""

    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    bytes_scanned: int
    source: str = ""
    source_kind: SourceKind = "text"

    @property
    def is_blocked(self) -> bool:
        return self.verdict is Verdict.DANGEROUS

    @property
    def has_warnings(self) -> bool:
        return self.verdict is not Verdict.CLEAN
