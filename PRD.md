# sniff — PRD

> A local-first prompt-injection scanner for AI agent inputs.

## Problem

Prompt injection is the kind of risk that people hear about and then
shy away from running agents locally because of it. Most existing tools
either:

- live in the cloud (so the "fix" introduces a new data-leak risk),
- are coupled to a specific agent framework, or
- only catch the obvious patterns and miss the rest.

`sniff` is the small, local tool you run on text — a file, a paste, a
URL — *before* it touches an agent. It is the seatbelt.

## Users

- **Primary (v0.1)**: BChop, personally. Used to gate inputs to local
  agents (Hermes, OpenClaw, anything custom).
- **Secondary (later)**: other solo devs and small teams running agents
  on their own machines, if the tool proves out.

## Non-goals (v0.1)

- Cloud-hosted scanning.
- LLM-as-judge style detection. Rules-only for now.
- Per-framework integrations (LangChain, OpenAI Assistants, Hermes
  hooks). The scanner core is decoupled to make those easy later.
- A web UI. CLI only.

## Core features

### P0 — must ship in v0.1

- **F0.1 CLI scanner.** `sniff [PATH]` reads a file or stdin, runs
  detection, prints a human-readable verdict.
- **F0.2 JSON output.** `sniff --format json` for programmatic use.
- **F0.3 Non-zero exit on warnings.** SUSPICIOUS = 2, DANGEROUS = 3,
  CLEAN = 0. Makes the CLI composable with shell pipelines.
- **F0.4 Default rule set.** At least five detection families covering
  instruction override, role hijack, system-tag forgery, tool-call
  forgery, and exfiltration hooks.
- **F0.5 Verdict model.** CLEAN / SUSPICIOUS / DANGEROUS rolled up from
  per-rule severity.
- **F0.6 Library API.** `from sniff.scanner import Scanner` works
  without the CLI.

### P1 — next

- **F1.1 Config file.** `.sniffrc` (or similar) to enable/disable rules,
  set per-rule severity overrides, and define allow/deny patterns.
- **F1.2 URL mode.** `sniff https://...` fetches and scans. Off by
  default in v0.1 — we keep network I/O out until the rules are
  trustworthy.
- **F1.3 Structured findings export.** SARIF output for CI integration.
- **F1.4 Library entry points per agent framework.** A small adapter
  per framework that wraps `Scanner.scan()` around the right message
  boundary.

### P2 — later

- **F2.1 Proxy / middleware.** A standalone server that intercepts
  outbound HTTP and inbound messages. **Architectural note:** this is
  the option-3 product from the original discussion. The scanner core
  is already decoupled from the CLI specifically to make this a
  thin-transport addition rather than a rewrite.
- **F2.2 Heuristic layer.** Embedding-based similarity to known-bad
  corpora, on-device only.
- **F2.3 Reporting.** Markdown/HTML summary across many scans.

## Architecture

```
sniff/
├── src/sniff/
│   ├── scanner/            # Detection core — no I/O, no CLI imports.
│   │   ├── models.py       # ScanInput, Finding, ScanResult, Verdict
│   │   ├── rules.py        # Rule dataclass + DEFAULT_RULES
│   │   └── scanner.py      # Scanner class — pure function in/out
│   └── cli/                # Thin transport around the scanner.
│       └── main.py
└── tests/
    ├── fixtures/           # Real-world-shaped text samples
    └── test_scanner.py
```

The hard rule: **the scanner must never import from `sniff.cli`.** That
is what keeps the proxy option open.

## Acceptance criteria (v0.1)

- `uv run pytest -q` passes.
- `uv run ruff check src tests` is clean.
- `uv run sniff tests/fixtures/clean_email.txt` exits 0 and prints
  CLEAN.
- `uv run sniff tests/fixtures/instruction_override.txt` exits 3,
  prints DANGEROUS, and lists at least one PI-INSTR-001 finding.
- `uv run sniff --format json <file>` emits valid JSON with a `verdict`
  field.

## Open questions

- Should the BOM-strip behavior be configurable for inputs that
  legitimately start with a BOM? (Probably no — but flagging it.)
- For F1.2 URL mode: how do we handle redirects, JS-rendered pages,
  paywalls? Probably out of scope for v1, document the gap.

## Out of scope (forever)

- Acting as a substitute for a real red-team review of any agent.
- Guaranteeing detection. The threat evolves; this is one layer, not
  the whole defense.
