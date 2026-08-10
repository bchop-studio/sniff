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

# Use a config file (TOML or JSON)
uv run sniff --config path/to/sniff.toml path/to/prompt.txt
```

Exit codes: `0` = CLEAN, `2` = SUSPICIOUS, `3` = DANGEROUS, `4` =
config error. Remappable via config. Makes the CLI composable with shell
pipelines and CI gates.

## Config

Drop a TOML file at one of these locations (first hit wins):

- the path passed to `--config`
- `./.sniffrc` (TOML or JSON, auto-detected)
- `$XDG_CONFIG_HOME/sniff/config.toml` (default `~/.config/sniff/config.toml`)

```toml
[rules.PI-INSTR-001]
enabled = true
severity = "critical"   # low | medium | high | critical

[exit_codes]
clean = 0
suspicious = 2
dangerous = 3
```

Unknown rule ids in the config raise an error at load time, so typos
fail loudly instead of silently dropping your override. See
[`examples/sniff.example.toml`](./examples/sniff.example.toml) for a
full template.

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
