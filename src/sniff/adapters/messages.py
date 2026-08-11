"""Message-boundary adapters for agent frameworks (F1.4).

Frameworks hand agents a list of messages — OpenAI/LangChain style dicts
({"role": "user", "content": "..."}), Hermes-style objects with
.role/.content attributes, and variants in between. The adapter pulls
the *untrusted* text out of that list and runs it through the scanner at
the message boundary, so each framework integration is a thin wrapper
instead of a rewrite.

Design decisions:

- "Untrusted" means user/tool/external content. Developer-authored
  messages (system, assistant) are skipped by default — scanning your
  own system prompt only produces false positives. Callers can widen or
  narrow the role set.
- Messages may be plain dicts or arbitrary objects with `role`/`content`
  attributes. LangChain messages (`.type`/`.content`, where type is
  "human"/"ai"/"system"/"tool") are mapped onto the role vocabulary.
  OpenAI-style multimodal content (a list of parts) contributes its
  text parts; anything else unrecognized is skipped, never fatal.
- The adapter never imports from `sniff.cli`. The seam holds.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from sniff.scanner.models import Finding, ScanInput, Verdict
from sniff.scanner.scanner import Scanner

#: Roles whose content comes from outside the developer's control.
#: "tool" covers OpenAI-style tool results; "function" the older name.
DEFAULT_SCANNED_ROLES: frozenset[str] = frozenset({"user", "tool", "function"})

#: LangChain's message vocabulary uses different words for the same
#: boundary; map them onto the role names the role policy understands.
_LANGCHAIN_TYPE_TO_ROLE: dict[str, str] = {
    "human": "user",
    "ai": "assistant",
    "system": "system",
    "tool": "tool",
    "function": "function",
    "chat": "user",
}

_MISSING = object()


def _coerce_text(content: Any) -> str | None:
    """Turn message content into scannable text, or None to skip.

    Plain strings pass through. A list of parts (OpenAI multimodal
    shape) contributes the `text` of each text part joined by spaces;
    a list with no text at all is skipped. Anything else is skipped.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            part["text"]
            for part in content
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ]
        if parts:
            return " ".join(parts)
    return None


def _extract(message: Any) -> tuple[str | None, str | None]:
    """Pull (role, text) out of a dict-shaped or attribute-shaped message.

    Accepts OpenAI-style `role` keys/attributes and LangChain-style
    `type` keys/attributes (mapped through _LANGCHAIN_TYPE_TO_ROLE).
    Returns (None, None) for shapes we don't understand — the caller
    treats those as skippable, not fatal.
    """
    if isinstance(message, dict):
        role = message.get("role")
        if role is None:
            role = message.get("type")
        content = message.get("content")
    else:
        role = getattr(message, "role", _MISSING)
        if role is _MISSING:
            role = getattr(message, "type", _MISSING)
        content = getattr(message, "content", _MISSING)
        if role is _MISSING and content is _MISSING:
            return None, None
        if role is _MISSING:
            role = None
        if content is _MISSING:
            content = None

    if not isinstance(role, str):
        return None, None
    role = _LANGCHAIN_TYPE_TO_ROLE.get(role.lower(), role.lower())
    return role, _coerce_text(content)


def _worst_verdict(verdicts: Iterable[Verdict]) -> Verdict:
    worst = Verdict.CLEAN
    for verdict in verdicts:
        if verdict is Verdict.DANGEROUS:
            return Verdict.DANGEROUS
        if verdict is Verdict.SUSPICIOUS:
            worst = Verdict.SUSPICIOUS
    return worst


class MessageScanResult:
    """Aggregated outcome of scanning a message list.

    `worst_verdict` rolls up every scanned message; `findings` pairs each
    Finding with the index of the message it came from so callers can
    point at the exact offending entry. `scanned`/`skipped` count how
    many list entries each happened to.
    """

    __slots__ = ("findings", "scanned", "skipped", "worst_verdict")

    def __init__(
        self,
        worst_verdict: Verdict,
        findings: list[tuple[int, Finding]],
        scanned: int,
        skipped: int,
    ) -> None:
        self.worst_verdict = worst_verdict
        self.findings = findings
        self.scanned = scanned
        self.skipped = skipped

    @property
    def is_blocked(self) -> bool:
        return self.worst_verdict is Verdict.DANGEROUS

    def __repr__(self) -> str:
        return (
            f"MessageScanResult(worst_verdict={self.worst_verdict.value!r}, "
            f"findings={len(self.findings)}, scanned={self.scanned}, "
            f"skipped={self.skipped})"
        )


def scan_messages(
    scanner: Scanner,
    messages: Iterable[Any],
    *,
    roles: frozenset[str] | set[str] | None = None,
) -> MessageScanResult:
    """Scan the untrusted messages in a framework message list.

    `scanner` is any configured Scanner. `messages` is the list a
    framework would hand to its model. `roles` overrides which roles are
    treated as untrusted; the default is DEFAULT_SCANNED_ROLES
    (user/tool/function). System and assistant messages are skipped
    unless explicitly included.
    """
    scanned_roles = DEFAULT_SCANNED_ROLES if roles is None else roles
    verdicts: list[Verdict] = []
    findings: list[tuple[int, Finding]] = []
    scanned = 0
    skipped = 0

    for index, message in enumerate(messages):
        role, text = _extract(message)
        if role is None or text is None or role not in scanned_roles:
            skipped += 1
            continue
        result = scanner.scan(
            ScanInput(content=text, source=f"messages[{index}]", source_kind="text")
        )
        scanned += 1
        verdicts.append(result.verdict)
        findings.extend((index, f) for f in result.findings)

    return MessageScanResult(
        worst_verdict=_worst_verdict(verdicts),
        findings=findings,
        scanned=scanned,
        skipped=skipped,
    )


__all__ = [
    "DEFAULT_SCANNED_ROLES",
    "MessageScanResult",
    "scan_messages",
]
