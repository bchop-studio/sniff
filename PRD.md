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

- [x] **P1.1 Config file.** `.sniffrc` (TOML/JSON) or
  `$XDG_CONFIG_HOME/sniff/config.toml`. Toggles rules, overrides per-rule
  severity, and remaps the CLEAN/SUSPICIOUS/DANGEROUS exit codes. Unknown
  rule ids are a hard error so typos don't get silently dropped.
- [x] **P1.2 URL mode.** `sniff --allow-url https://...` fetches and
  scans. Network I/O is opt-in: without the flag a URL target is
  refused with a clear error. Fetches are SSRF-guarded — http(s) only,
  no credentials in URLs, public IPs only (loopback, private,
  link-local including cloud metadata, multicast, reserved all
  refused), every redirect hop re-validated and capped, 1 MiB body
  limit (over-limit is an error, never silent truncation), 10s timeout.
  DNS rebinding is mitigated by re-validating every connection-time DNS
  answer against the same block list (`guarded_getaddrinfo` in
  `src/sniff/cli/url_fetch.py`). JS-rendered pages and paywalls are out
  of scope: sniff scans whatever the server returns.
- [x] **F1.3 Structured findings export.** SARIF 2.1.0 output via
  `sniff --format sarif` for CI integration (GitHub code scanning,
  Azure DevOps, VS Code SARIF viewer). The exporter lives in the
  scanner core (`sniff.scanner.sarif.result_to_sarif`) so the library
  and any future transport get it for free. Sniff severities map onto
  SARIF levels (CRITICAL → error, HIGH/MEDIUM → warning, LOW → note),
  every rule carries its metadata under `tool.driver.rules`, and each
  finding gets a `charOffset` region into the scanned source.
- [x] **F1.4 Library entry points per agent framework.** A small adapter
  per framework that wraps `Scanner.scan()` around the right message
  boundary. Shipped as `sniff.adapters.scan_messages(scanner, messages)`:
  a framework-agnostic entry point that accepts OpenAI/LangChain-style
  message dicts and Hermes/SDK-style objects with `.role`/`.content`
  attributes (plus LangChain's `.type`/`.content` shape, where
  "human"/"ai"/"system" map onto the role vocabulary), scans the
  untrusted roles (user/tool/function by default, overridable), joins
  OpenAI-style multimodal text parts into scannable text, skips
  developer-authored system/assistant messages, and rolls the
  per-message results up into one `MessageScanResult` with each finding
  tied to its message index. Per-framework integrations are thin
  wrappers over this; no framework SDK is a dependency of sniff.

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
│   │   ├── sarif.py        # SARIF 2.1.0 export (F1.3)
│   │   └── scanner.py      # Scanner class — pure function in/out
│   ├── adapters/           # Framework entry points (F1.4) — no CLI imports.
│   │   └── messages.py     # scan_messages: chat message lists in, verdict out
│   └── cli/                # Thin transport around the scanner.
│       └── main.py
└── tests/
    ├── fixtures/           # Real-world-shaped text samples
    └── test_scanner.py
```

The hard rule: **the scanner and adapters must never import from
`sniff.cli`.** That is what keeps the proxy option open.

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
- ~~For F1.2 URL mode: how do we handle redirects, JS-rendered pages,
  paywalls?~~ Resolved in P1.2: redirects are followed (each hop
  re-validated, capped at 5). JS-rendered pages and paywalls stay out
  of scope — sniff scans the raw response body.

## Out of scope (forever)

- Acting as a substitute for a real red-team review of any agent.
- Guaranteeing detection. The threat evolves; this is one layer, not
  the whole defense.
