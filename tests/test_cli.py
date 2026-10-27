"""End-to-end tests for the command line interface."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


class _Result:
    """subprocess result whose stdout/stderr are always str.

    Communication happens in bytes so the payload can carry arbitrary Unicode
    regardless of the parent's locale; decoding afterwards keeps every existing
    assertion working on Windows and Linux alike.
    """

    def __init__(self, completed: subprocess.CompletedProcess) -> None:
        self.returncode = completed.returncode
        self.stdout = completed.stdout.decode("utf-8", errors="replace")
        self.stderr = completed.stderr.decode("utf-8", errors="replace")


def run_cli(*args, cwd=None, stdin=None):
    # stdin is encoded here on purpose: subprocess would otherwise use the
    # platform preferred encoding (cp1252 on Windows), which cannot carry
    # U+200B. The child emits UTF-8 because cli.main() forces it.
    payload = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
    completed = subprocess.run(
        [PY, "-m", "invisiscan", *args],
        cwd=str(cwd or ROOT),
        capture_output=True,
        input=payload,
    )
    return _Result(completed)


def test_version_flag():
    assert run_cli("--version").stdout.strip() == "invisiscan 1.0.0"


def test_help_lists_rule_catalogue():
    out = run_cli("--help").stdout
    assert "rule catalogue" in out
    assert "IS001" in out and "IS010" in out


def test_clean_file_exits_zero(tmp_path):
    target = tmp_path / "ok.py"
    target.write_text("x = 1\n", encoding="utf-8")
    proc = run_cli(str(target))
    assert proc.returncode == 0
    assert "0 total finding(s)" in proc.stdout


def test_dirty_file_exits_one(tmp_path):
    target = tmp_path / "bad.py"
    target.write_text("x = '​'\n", encoding="utf-8")
    proc = run_cli(str(target))
    assert proc.returncode == 1
    assert "U+200B" in proc.stdout


def test_missing_path_exits_two(tmp_path):
    proc = run_cli(str(tmp_path / "nope.py"))
    assert proc.returncode == 2
    assert "no such path" in proc.stderr


def test_empty_directory_exits_two(tmp_path):
    (tmp_path / "empty").mkdir()
    proc = run_cli(str(tmp_path / "empty"))
    assert proc.returncode == 2


def test_stdin_mode():
    proc = run_cli("--stdin", stdin="a​b\n")
    assert proc.returncode == 1
    assert "<stdin>" in proc.stdout


def test_stdin_name_is_used():
    proc = run_cli("--stdin", "--stdin-name", "policy.yaml", stdin="a​b\n")
    assert "policy.yaml" in proc.stdout


def test_json_format_is_parseable(tmp_path):
    target = tmp_path / "bad.py"
    target.write_text("x = '﻿'", encoding="utf-8")
    proc = run_cli(str(target), "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["summary"]["findings"] >= 1
    assert payload["results"][0]["rule"] == "IS002"


def test_sarif_format_is_parseable(tmp_path):
    target = tmp_path / "bad.py"
    target.write_text("x = '​'", encoding="utf-8")
    proc = run_cli(str(target), "--format", "sarif")
    payload = json.loads(proc.stdout)
    assert payload["runs"][0]["tool"]["driver"]["name"] == "InvisiScan"
    assert len(payload["runs"][0]["results"]) >= 1


def test_severity_threshold_filters(tmp_path):
    target = tmp_path / "mixed.py"
    target.write_text("a​b c", encoding="utf-8")  # HIGH zero-width + MEDIUM nbsp
    all_out = run_cli(str(target), "--format", "json").stdout
    crit_out = run_cli(str(target), "--severity", "critical", "--format", "json").stdout
    assert len(json.loads(all_out)["results"]) == 2
    assert json.loads(crit_out)["results"] == []


def test_ignore_rule(tmp_path):
    target = tmp_path / "bad.py"
    target.write_text("a​b", encoding="utf-8")
    assert run_cli(str(target)).returncode == 1
    assert run_cli(str(target), "--ignore", "IS002").returncode == 0


def test_only_rule(tmp_path):
    target = tmp_path / "bad.py"
    target.write_text("a​b", encoding="utf-8")
    assert run_cli(str(target), "--rule", "IS002").returncode == 1
    assert run_cli(str(target), "--rule", "IS007").returncode == 0


def test_unknown_rule_rejected(tmp_path):
    proc = run_cli(str(tmp_path), "--rule", "ZZ999")
    assert proc.returncode != 0
    assert "unknown rule id" in proc.stderr


def test_extension_filter(tmp_path):
    good = tmp_path / "skip.md"
    evil = tmp_path / "keep.py"
    good.write_text("x​", encoding="utf-8")
    evil.write_text("y", encoding="utf-8")
    proc = run_cli(str(tmp_path), "--extension", ".md", "--format", "json")
    paths = {r["file"] for r in json.loads(proc.stdout)["results"]}
    assert any("skip.md" in p for p in paths)
    assert not any("keep.py" in p for p in paths)


def test_exclude_pattern(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("x​", encoding="utf-8")
    (tmp_path / "app.py").write_text("x​", encoding="utf-8")
    proc = run_cli(str(tmp_path), "--exclude", "vendor", "--format", "json")
    paths = {r["file"] for r in json.loads(proc.stdout)["results"]}
    assert not any("vendor" in p for p in paths)
    assert any("app.py" in p for p in paths)


def test_no_confusables_flag(tmp_path):
    target = tmp_path / "h.py"
    target.write_text("admin = 1\nаdmin = 2\n", encoding="utf-8")
    assert run_cli(str(target)).returncode == 1
    assert run_cli(str(target), "--no-confusables").returncode == 0


def test_fixtures_directory_detects_every_attack():
    proc = run_cli("tests/fixtures", "--format", "json")
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    rules = {r["rule"] for r in payload["results"]}
    assert {"IS001", "IS002", "IS004", "IS007", "IS010"} <= rules


def test_scanner_reports_zero_findings_on_own_source():
    """The tool must be clean by its own standard."""
    proc = run_cli("invisiscan", "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["summary"]["findings"] == 0, json.dumps(payload["results"], indent=2)


def test_installed_entry_point():
    """If the console script is on PATH it must work; absence is not a failure."""
    if shutil.which("invisiscan") is None:
        pytest.skip("console script not on PATH")
    proc = subprocess.run(["invisiscan", "--version"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "invisiscan 1.0.0"
