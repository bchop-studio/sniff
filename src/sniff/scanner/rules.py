"""Detection rules for sniff.

Each Rule is a small, testable unit: an id, a regex, a severity, and a
human-readable rationale. The scanner runs them in order; ordering does not
affect the verdict, only the order findings are reported.

Rules are intentionally simple regex matches. The goal at this stage is to
catch the bulk of obvious injections with low false-positive cost; layered
heuristics land later once we see what real attacks look like against
BChop's agents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sniff.scanner.models import Severity


@dataclass(frozen=True)
class Rule:
    """A single detection rule."""

    rule_id: str
    name: str
    severity: Severity
    pattern: re.Pattern[str]
    rationale: str
    # Window (chars) to grab around the match for the excerpt. Keeps the
    # CLI output readable instead of dumping the whole document.
    excerpt_window: int = 80


# --- Rule families ---------------------------------------------------------
#
# 1. Instruction overrides — explicit attempts to make the model discard
#    its prior instructions and follow new ones.
#
# 2. Role / persona hijacks — tries to install a different "system" voice.
#
# 3. System-tag forgery — fake <system>, [INST], <|im_start|> tags that
#    some agent frameworks still honor naively.
#
# 4. Tool-call forgery — fake JSON function calls or <tool_use> blocks.
#
# 5. Data-exfiltration hooks — instructions that try to make the model
#    forward data to an attacker-controlled endpoint.


_INSTRUCTION_OVERRIDE = re.compile(
    r"""
    (?ix)
    \b(
        ignore\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|previous\s+|prior\s+)+instructions?
      | disregard\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|previous\s+|prior\s+)+instructions?
      | forget\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|previous\s+|prior\s+)+instructions?
      | do\s+not\s+follow\s+(?:the\s+)?(?:previous|prior|above)\s+instructions?
      | new\s+instructions?\s*:
      | override\s+instructions?
      | system\s+override
    )
    """,
    re.VERBOSE,
)


_ROLE_HIJACK = re.compile(
    r"""
    (?ix)
    \b(
        you\s+are\s+now\s+
      | act\s+as\s+(?:a\s+|an\s+)?(?:jailbroken|uncensored|unfiltered|developer\s+mode)\s+
      | pretend\s+(?:to\s+be|you\s+are)\s+
      | from\s+now\s+on\s+you\s+are
      | your\s+new\s+role\s+is
      | enter\s+(?:developer|dan|debug)\s+mode
    )
    """,
    re.VERBOSE,
)


_SYSTEM_TAG_FORGERY = re.compile(
    r"""
    (?x)
    (?:
        <\s*(?:system|assistant|tool|tool_use|tool_result)\s*>
      | \[INST\]
      | <\|im_start\|>\s*(?:system|assistant)
      | <\|im_end\|>
      | <<\s*SYS\s*>>
      | \[/?SYSTEM\]
    )
    """,
    re.VERBOSE,
)


_TOOL_CALL_FORGERY = re.compile(
    r"""
    (?x)
    (?:
        \{\s*"name"\s*:\s*"[^"]+"\s*,\s*"arguments"\s*:
      | <tool_use>\s*\{[^}]*"name"
      | <antml:function_calls>
      | ```json\s*\{\s*"tool_calls?"
    )
    """,
    re.VERBOSE,
)


_EXFIL_HOOK = re.compile(
    r"""
    (?ix)
    \b(
        send\s+(?:this|the|that|my|your|a)\s+(?:result|output|response|content|message|prompt|data)\s+to\s+
      | forward\s+(?:this|the|that|my|your|a)\s+(?:result|output|response|content|message|prompt|data)\s+to\s+
      | post\s+(?:this|the|that|my|your|a)\s+(?:result|output|response|content|message|prompt|data)\s+to\s+
      | include\s+(?:the|this|that|my|your|a)\s+(?:result|output|response|content|message|prompt|data)\s+in\s+(?:a\s+)?(?:http|curl|fetch|request)
      | curl\s+[^|;\n]*\$\{?
      | webhook\.site|requestbin\.com|hookbin\.com
    )
    """,
    re.VERBOSE,
)


DEFAULT_RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="PI-INSTR-001",
        name="Instruction override",
        severity=Severity.CRITICAL,
        pattern=_INSTRUCTION_OVERRIDE,
        rationale=(
            "Text tries to discard or override prior instructions. This is "
            "the canonical shape of a prompt-injection payload."
        ),
    ),
    Rule(
        rule_id="PI-ROLE-001",
        name="Role / persona hijack",
        severity=Severity.HIGH,
        pattern=_ROLE_HIJACK,
        rationale=(
            "Text tries to install a new persona (jailbroken, dev mode, "
            "etc.) that bypasses the model's safety framing."
        ),
    ),
    Rule(
        rule_id="PI-SYS-001",
        name="System-tag forgery",
        severity=Severity.HIGH,
        pattern=_SYSTEM_TAG_FORGERY,
        rationale=(
            "Text contains fake system/assistant/tool control tags. "
            "Naive agent runtimes will honor these as if they came from "
            "the developer."
        ),
    ),
    Rule(
        rule_id="PI-TOOL-001",
        name="Tool-call forgery",
        severity=Severity.CRITICAL,
        pattern=_TOOL_CALL_FORGERY,
        rationale=(
            "Text contains a forged function-call or tool-use block. "
            "Untrusted input should never be allowed to mint tool calls."
        ),
    ),
    Rule(
        rule_id="PI-EXFIL-001",
        name="Data-exfiltration hook",
        severity=Severity.HIGH,
        pattern=_EXFIL_HOOK,
        rationale=(
            "Text instructs the model to forward data to an external "
            "endpoint, or names a known exfiltration host."
        ),
    ),
)
