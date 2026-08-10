# sniff — Agent Operating Manual

This file is for AI agents (Hestia, subagents, future-you) working in
this repo. Humans are welcome to read it too.

## Cardinal rule

**Never edit `main` directly.** All changes go through a feature
branch and a pull request. BChop reviews and merges. The only
exception is the initial bootstrap commit (already done).

After a merge:

1. Sync `main` locally.
2. Delete the merged branch.
3. Prune remote-tracking refs.

## Security rules

- **Never commit secrets.** API keys, tokens, webhook URLs, customer
  data, anything that should not be public. Real keys belong in
  `.env` (which is gitignored), never in code or in test fixtures.
- **Never print credentials.** If a secret is visible in a tool
  result, say "there's a credential here, I'm not saying it" and let
  the human decide.
- **No generated media, no model weights, no watermarked AI output
  gets committed.** This is not a model repo.
- **Secret scan before every commit.** A grep for
  `(api[_-]?key|token|secret|password|webhook)` against the staged
  diff, excluding `.env.example`, is the minimum.

## Code rules

- Python 3.11+. Use `from __future__ import annotations` in new
  modules.
- Type hints on all public functions and methods.
- Pydantic v2 for data models. No dataclasses in the public API.
- The scanner must not import from `sniff.cli`. Keep the seam clean
  so the proxy can land later.
- Lint with `uv run ruff check src tests`. No new warnings.
- Tests with `uv run pytest -q`. New logic needs new tests.

## Verification before commit

Run, in order:

1. `uv run ruff check src tests`
2. `uv run pytest -q`
3. `uv run sniff tests/fixtures/clean_email.txt` — must exit 0.
4. `uv run sniff tests/fixtures/instruction_override.txt` — must
   exit 3 with a DANGEROUS verdict.

A change that breaks any of these is not ready for review.

## What lives where

- `src/sniff/scanner/` — detection logic. No I/O, no CLI imports.
  This is the seam.
- `src/sniff/cli/` — click entrypoint. Reads input, calls
  `Scanner.scan()`, formats output.
- `tests/fixtures/` — text samples used by both the test suite and
  manual CLI demos. Add new samples here when adding a new rule.
- `PRD.md` — source of truth for what to build. Update it when scope
  changes.

## When adding a new rule

1. Write the regex in `src/sniff/scanner/rules.py`. Give it a stable
   `rule_id` in the `PI-<FAMILY>-<NNN>` shape.
2. Add a fixture under `tests/fixtures/` containing a payload that
   matches and a payload that does not.
3. Add tests in `tests/test_scanner.py`.
4. Update `PRD.md` rule count if it was a F0.4 commitment.
5. Run all four verification steps above.
