import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_security_baseline_covers_release_checks() -> None:
    workflow = _read(WORKFLOWS / "security-baseline.yml")

    assert "pull_request:" in workflow
    assert 'branches: ["main"]' in workflow
    assert "schedule:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "uv lock --check" in workflow
    assert "uv run ruff check ." in workflow
    assert "uv run pytest" in workflow
    assert "uv build" in workflow
    assert "pip-audit" in workflow
    assert "Sensitive tracked filenames" in workflow


def test_codeql_scans_python_and_workflows() -> None:
    workflow = _read(WORKFLOWS / "codeql.yml")

    assert "security-events: write" in workflow
    assert "language: [python, actions]" in workflow
    assert "queries: security-extended" in workflow
    assert "github/codeql-action/init@" in workflow
    assert "github/codeql-action/analyze@" in workflow


def test_all_remote_actions_are_pinned_to_full_commits() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        for line in _read(path).splitlines():
            stripped = line.strip()
            if not stripped.startswith("uses:") or stripped.startswith("uses: ./"):
                continue
            reference = stripped.split("#", 1)[0].split("@", 1)[1].strip()
            assert FULL_SHA.fullmatch(reference), f"Unpinned action in {path}: {line}"


def test_dependabot_groups_uv_and_actions_weekly() -> None:
    config = _read(ROOT / ".github" / "dependabot.yml")

    assert 'package-ecosystem: "uv"' in config
    assert 'package-ecosystem: "github-actions"' in config
    assert config.count('multi-ecosystem-group: "weekly-dependencies"') == 2
    assert config.count('interval: "weekly"') == 1
    assert 'day: "monday"' in config
    assert 'time: "10:00"' in config
    assert 'timezone: "America/New_York"' in config
