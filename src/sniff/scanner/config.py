"""Configuration loader for sniff.

Reads a JSON or TOML file that lets callers toggle rules, override
per-rule severity, and remap the CLEAN/SUSPICIOUS/DANGEROUS exit codes.

Discovery order (first hit wins):
  1. The `--config <path>` flag on the CLI.
  2. `./.sniffrc` in the current working directory.
  3. `$XDG_CONFIG_HOME/sniff/config.toml` (default `~/.config/sniff/config.toml`).
  4. `Config()` defaults — empty overrides, exit codes 0/2/3.

Unknown rule ids raise `ConfigError`. The scanner silently dropping an
override because of a typo is the failure mode this guards against.
"""

from __future__ import annotations

import json
import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sniff.scanner.models import Severity

# POSIX exit codes are 0-255. We bound at 255 so the config catches
# obvious typos (e.g. 1000) while staying useful for any CI integration.
ExitCode = int


class ConfigError(ValueError):
    """Raised when a config file is malformed, has the wrong shape, or
    references an unknown rule id."""


class RuleOverride(BaseModel):
    """Per-rule override applied on top of the built-in defaults."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    severity: Severity | None = None


class ExitCodes(BaseModel):
    """Exit-code remapping. Any verdict not listed keeps its default."""

    model_config = ConfigDict(extra="forbid")

    clean: ExitCode = 0
    suspicious: ExitCode = 2
    dangerous: ExitCode = 3

    @field_validator("clean", "suspicious", "dangerous")
    @classmethod
    def _in_posix_range(cls, v: int) -> int:
        if not 0 <= v <= 255:
            raise ValueError(f"exit code must be 0-255, got {v}")
        return v


class Config(BaseModel):
    """The full sniff configuration.

    `rules` is keyed by rule id (e.g. "PI-INSTR-001"). Every entry must
    reference a rule id that the running Scanner actually knows about;
    the loader validates that against a passed-in rule-id set.
    """

    model_config = ConfigDict(extra="forbid")

    rules: dict[str, RuleOverride] = Field(default_factory=dict)
    exit_codes: ExitCodes = Field(default_factory=ExitCodes)

    @field_validator("rules")
    @classmethod
    def _no_empty_keys(cls, v: dict[str, RuleOverride]) -> dict[str, RuleOverride]:
        for key in v:
            if not key.strip():
                raise ValueError("rule id keys must be non-empty")
        return v

    @classmethod
    def load(
        cls,
        path: Path | None = None,
        *,
        known_rule_ids: set[str] | None = None,
    ) -> Config:
        """Load a Config from `path`, or discover one, or return defaults.

        `known_rule_ids` is the set of rule ids the caller intends to use.
        If a config file references an id outside that set, raise
        ConfigError so typos are caught at load time, not at scan time.
        """
        if path is None:
            path = _find_default_config()
        if path is None:
            return cls()
        return load_config(path, known_rule_ids=known_rule_ids)


# --- Discovery -------------------------------------------------------------


def _default_user_config_path() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "sniff" / "config.toml"


_SEARCH_PATHS: tuple[Path, ...] = (
    Path.cwd() / ".sniffrc",
    _default_user_config_path(),
)


def _find_default_config() -> Path | None:
    """Return the first existing default config path, or None."""
    for candidate in _SEARCH_PATHS:
        if candidate.is_file():
            return candidate
    return None


# --- Parsing ---------------------------------------------------------------


def _parse_file(path: Path) -> dict[str, object]:
    """Read a config file. JSON or TOML, decided by extension."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file {path}: {exc}") from exc

    suffix = path.suffix.lower()
    name = path.name.lower()
    try:
        if suffix == ".json" or name == ".sniffrc":
            data = json.loads(text)
        elif suffix in {".toml", ""}:
            # `.toml` is the TOML signal. An empty suffix on a file that
            # isn't `.sniffrc` is treated as a config typo rather than
            # silently falling through to TOML — see the `else` below.
            data = tomllib.loads(text)
        else:
            raise ConfigError(
                f"unsupported config file extension {suffix!r} on {path.name} "
                "(use .json, .toml, or .sniffrc)"
            )
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a top-level object/table, got {type(data).__name__}")
    return data


# --- Public API ------------------------------------------------------------


def load_config(
    path: Path | None = None,
    *,
    known_rule_ids: set[str] | None = None,
) -> Config:
    """Load a Config from `path`, or discover one, or return defaults.

    `known_rule_ids` is the set of rule ids the caller intends to use.
    If a config file references an id outside that set, raise ConfigError
    so typos are caught at load time, not at scan time.
    """
    if path is None:
        path = _find_default_config()
    if path is None:
        return Config()

    data = _parse_file(path)
    try:
        cfg = Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"{path} failed validation:\n{exc}") from exc

    if known_rule_ids is not None:
        unknown = set(cfg.rules) - known_rule_ids
        if unknown:
            unknown_list = ", ".join(sorted(unknown))
            raise ConfigError(
                f"{path} references unknown rule id(s): {unknown_list}. "
                f"Known ids: {', '.join(sorted(known_rule_ids))}."
            )

    return cfg
