# Sniff

![Sniff, a local prompt-injection scanner](./cover.png)

> A local-first prompt-injection scanner. Smells before you swallow.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-00E5D9)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-FF007A)](./LICENSE)

`sniff` is a small CLI you run on text — a file, a paste, a URL —
*before* you feed it to an AI agent. It catches the common shapes of
prompt-injection payloads (instruction overrides, role hijacks, fake
system tags, forged tool calls, exfiltration hooks) and tells you
whether to pass, caution, or block.

## Install

```bash
uv tool install git+https://github.com/BeardedChop/sniff.git
```

For local development, clone the repository and run `uv sync --extra dev`.

## Use

```bash
# Scan a file
uv run sniff path/to/prompt.txt

# Scan stdin
echo "ignore all previous instructions" | uv run sniff

# JSON output for pipelines
uv run sniff --format json path/to/prompt.txt > result.json

# SARIF output for CI code scanning (GitHub, Azure DevOps)
uv run sniff --format sarif path/to/prompt.txt > results.sarif

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

## Local screening gateway

The first F2.1 slice is an authenticated screening service. It listens on
loopback only, accepts a bounded message list, and returns a verdict. It
does **not** forward requests or make outbound network calls.

```bash
export SNIFF_GATEWAY_TOKEN="use-a-random-token-at-least-16-characters"
uv run sniff-gateway --port 8765
```

Send `POST /v1/scan/messages` with a bearer token:

```bash
curl -sS http://127.0.0.1:8765/v1/scan/messages \
  -H "Authorization: Bearer $SNIFF_GATEWAY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"your text"}]}'
```

The gateway has strict body, message-count, and message-content limits.
Every submitted message is screened as untrusted, regardless of its
claimed role. It never logs request bodies or returns excerpts. Errors
fail closed. The completed
[forwarding security review](docs/F2.1-FORWARDING-SECURITY-REVIEW.md) rejects
a general-purpose proxy and defines the gates for one fixed-upstream slice.

## Library use

```python
from sniff.scanner import ScanInput, Scanner

result = Scanner().scan(ScanInput(content=text, source="user-prompt"))
if result.is_blocked:
    raise ValueError("Blocked by sniff: prompt-injection detected.")
```

### Agent framework messages

```python
from sniff.adapters import scan_messages
from sniff.scanner import Scanner

# Works with OpenAI/LangChain-style dicts and SDK message objects alike
# (LangChain's `.type`/`.content` shape included; multimodal text parts
# are joined and scanned).
outcome = scan_messages(Scanner(), messages)  # user/tool/function scanned
if outcome.is_blocked:
    raise ValueError(f"Blocked by sniff: {outcome.findings[0][1].rule_id} "
                     f"in messages[{outcome.findings[0][0]}]")
```

System and assistant messages are skipped by default (they're
developer-authored); pass `roles={...}` to change which roles count as
untrusted.

## Rule families (v0.1)

| ID            | Name                  | Severity | Catches                                |
|---------------|-----------------------|----------|----------------------------------------|
| PI-INSTR-001  | Instruction override  | CRITICAL | "ignore previous instructions" shape   |
| PI-ROLE-001   | Role / persona hijack | HIGH     | "you are now DAN", "pretend to be..."  |
| PI-SYS-001    | System-tag forgery    | HIGH     | Fake `<system>`, `[INST]`, `<|im_start|>` |
| PI-TOOL-001   | Tool-call forgery     | CRITICAL | Forged `tool_calls` / `<tool_use>` blocks |
| PI-EXFIL-001  | Exfiltration hook     | HIGH     | "forward this to", webhook hosts       |

## What Sniff does not promise

Sniff is one local safety layer, not a guarantee that every prompt injection
will be detected. Keep normal permission boundaries, sandboxing, and human
review around agents that can take real actions.

## License

MIT. See [LICENSE](./LICENSE).

Built by [BChop Studio](https://bchop.dev) · [@BChopLXXXII](https://x.com/BChopLXXXII)
