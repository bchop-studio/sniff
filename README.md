# sniff

> A local-first prompt-injection scanner. Smells before you swallow.

`sniff` is a small CLI you run on text — a file, a paste, a URL —
*before* you feed it to an AI agent. It catches the common shapes of
prompt-injection payloads (instruction overrides, role hijacks, fake
system tags, forged tool calls, exfiltration hooks) and tells you
whether to pass, caution, or block.

## Install

```bash
# from the project root
uv venv
uv pip install -e '.[dev]'
```

## Use

```bash
# Scan a file
uv run sniff path/to/prompt.txt

# Scan stdin
echo "ignore all previous instructions" | uv run sniff

# JSON output for pipelines
uv run sniff --format json path/to/prompt.txt > result.json
```

Exit codes: `0` = CLEAN, `2` = SUSPICIOUS, `3` = DANGEROUS. Makes the
CLI composable with shell pipelines and CI gates.

## Library use

```python
from sniff.scanner import ScanInput, Scanner

result = Scanner().scan(ScanInput(content=text, source="user-prompt"))
if result.is_blocked:
    raise ValueError("Blocked by sniff: prompt-injection detected.")
```

## Rule families (v0.1)

| ID            | Name                  | Severity | Catches                                |
|---------------|-----------------------|----------|----------------------------------------|
| PI-INSTR-001  | Instruction override  | CRITICAL | "ignore previous instructions" shape   |
| PI-ROLE-001   | Role / persona hijack | HIGH     | "you are now DAN", "pretend to be..."  |
| PI-SYS-001    | System-tag forgery    | HIGH     | Fake `<system>`, `[INST]`, `<|im_start|>` |
| PI-TOOL-001   | Tool-call forgery     | CRITICAL | Forged `tool_calls` / `<tool_use>` blocks |
| PI-EXFIL-001  | Exfiltration hook     | HIGH     | "forward this to", webhook hosts       |

## Status

Private. v0.1 alpha. Built for BChop's own local agents first.

See [PRD.md](./PRD.md) for the full plan, [AGENTS.md](./AGENTS.md) for
how agents working in this repo are expected to behave.
