"""CLI transport for sniff.

This module is intentionally thin. All detection lives in
`sniff.scanner`; the CLI's job is just to get bytes from somewhere and
hand them to `Scanner.scan(...)`. The proxy will reuse the scanner the
same way.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sniff.cli import url_fetch
from sniff.cli.url_fetch import FetchError
from sniff.scanner import Config, ConfigError, ScanInput, Scanner
from sniff.scanner.models import ScanResult, Severity, Verdict
from sniff.scanner.rules import Rule
from sniff.scanner.sarif import result_to_sarif

console = Console(stderr=True)
stdout_console = Console()


def _verdict_style(verdict: Verdict) -> str:
    return {
        Verdict.CLEAN: "bold green",
        Verdict.SUSPICIOUS: "bold yellow",
        Verdict.DANGEROUS: "bold red",
    }[verdict]


def _severity_style(severity: Severity) -> str:
    return {
        Severity.LOW: "blue",
        Severity.MEDIUM: "yellow",
        Severity.HIGH: "red",
        Severity.CRITICAL: "bold red",
    }[severity]


def _print_human(result: ScanResult) -> None:
    style = _verdict_style(result.verdict)
    header = f"[{style}]{result.verdict.value.upper()}[/{style}]"
    summary = (
        f"{header}  ·  {len(result.findings)} finding(s)  ·  "
        f"{result.bytes_scanned} bytes  ·  source: {result.source or '<stdin>'}"
    )
    console.print(Panel(summary, title="sniff", border_style=style.split()[-1]))

    if not result.findings:
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Offset", justify="right")
    table.add_column("Excerpt", overflow="fold")
    for f in result.findings:
        sev = f"[{_severity_style(f.severity)}]{f.severity.value}[/{_severity_style(f.severity)}]"
        table.add_row(f.rule_id, sev, str(f.offset), f.excerpt)
    console.print(table)

    console.print()
    console.print("[dim]Rationale (first finding):[/dim]")
    console.print(f"  {result.findings[0].rationale}")


def _print_json(result: ScanResult) -> None:
    stdout_console.print_json(result.model_dump_json())


def _print_sarif(result: ScanResult, rules: tuple[Rule, ...]) -> None:
    stdout_console.print_json(json.dumps(result_to_sarif(result, rules)))


def _read_text_from_stdin() -> str:
    return sys.stdin.read()


def _url_scheme(target: str) -> str | None:
    """Return the lowercase scheme if `target` is URL-shaped, else None.

    'URL-shaped' means it has a scheme followed by '://', so plain file
    paths (including Windows-style 'C:\\...') stay on the file path.
    """
    if "://" not in target:
        return None
    scheme = target.split("://", 1)[0].lower()
    return scheme or None


def _read_text_from_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _exit_code_for(result: ScanResult, cfg: Config) -> int:
    """Map a verdict to the configured exit code (0/2/3 by default)."""
    return {
        Verdict.CLEAN: cfg.exit_codes.clean,
        Verdict.SUSPICIOUS: cfg.exit_codes.suspicious,
        Verdict.DANGEROUS: cfg.exit_codes.dangerous,
    }[result.verdict]


@click.command(
    name="sniff",
    help="Scan text for prompt-injection patterns before you feed it to an agent.",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.argument(
    "target",
    metavar="[PATH|URL]",
    required=False,
)
@click.option(
    "--allow-url",
    is_flag=True,
    default=False,
    help=(
        "Allow TARGET to be an http(s) URL that sniff fetches and scans. "
        "Off by default: network I/O is opt-in. Fetches are SSRF-guarded "
        "(public IPs only, no credentials, bounded size)."
    ),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["human", "json", "sarif"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format. 'sarif' emits SARIF 2.1.0 for CI code scanning.",
)
@click.option(
    "--exit-code/--no-exit-code",
    default=True,
    help=(
        "Exit non-zero when verdict is suspicious or dangerous. Disable for "
        "wrappers that want to inspect output without aborting."
    ),
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help=(
        "Path to a config file (JSON or TOML). Overrides discovery "
        "(.sniffrc, $XDG_CONFIG_HOME/sniff/config.toml)."
    ),
)
def cli(
    target: str | None, allow_url: bool, fmt: str, exit_code: bool, config_path: Path | None
) -> None:
    # Load config first so a malformed file fails fast, before any text
    # scanning happens. Known rule ids come from the default rule set;
    # if a future caller passes a custom rule set, that moves here too.
    known_rule_ids = {r.rule_id for r in Scanner().rules}
    # Scanner() with default args sees the un-overridden ruleset, which is
    # exactly the set we want to validate against.

    try:
        cfg = Config.load(
            config_path,
            known_rule_ids=known_rule_ids,
        )
    except ConfigError as exc:
        console.print(f"[bold red]config error:[/bold red] {exc}")
        sys.exit(4)

    if target is None:
        text = _read_text_from_stdin()
        source = "<stdin>"
        kind = "text"
    elif _url_scheme(target) is not None:
        if not allow_url:
            console.print(
                "[bold red]error:[/bold red] URL targets are opt-in. "
                "Re-run with --allow-url to fetch and scan "
                f"{target!r}."
            )
            sys.exit(1)
        if _url_scheme(target) not in ("http", "https"):
            console.print(
                f"[bold red]error:[/bold red] cannot fetch {target!r}: only "
                "http and https URLs are supported."
            )
            sys.exit(1)
        try:
            text = url_fetch.fetch_url(target)
        except FetchError as exc:
            console.print(f"[bold red]fetch error:[/bold red] {exc}")
            sys.exit(1)
        source = target
        kind = "url"
    else:
        path = Path(target)
        if not path.is_file():
            console.print(f"[bold red]error:[/bold red] file {target!r} does not exist.")
            sys.exit(1)
        text = _read_text_from_file(path)
        source = str(path)
        kind = "file"

    scanner = Scanner(config=cfg)
    result = scanner.scan(ScanInput(content=text, source=source, source_kind=kind))

    if fmt == "json":
        _print_json(result)
    elif fmt == "sarif":
        _print_sarif(result, scanner.rules)
    else:
        _print_human(result)

    if exit_code:
        sys.exit(_exit_code_for(result, cfg))
