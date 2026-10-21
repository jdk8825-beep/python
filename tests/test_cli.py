import io
import json
from pathlib import Path

from iam_policy_checker.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_policy_exits_zero(capsys):
    assert main([str(FIXTURES / "least_privilege.json")]) == EXIT_OK
    assert "0 finding(s)" in capsys.readouterr().out


def test_admin_policy_fails(capsys):
    assert main([str(FIXTURES / "admin.json")]) == EXIT_FINDINGS
    assert "[CRITICAL] IAM001" in capsys.readouterr().out


def test_fail_on_none_always_exits_zero():
    assert main([str(FIXTURES / "admin.json"), "--fail-on", "none"]) == EXIT_OK


def test_fail_on_threshold_above_findings():
    # The escalation fixture's worst finding is CRITICAL, so only "none" passes.
    assert main([str(FIXTURES / "escalation.json"), "--fail-on", "critical"]) == EXIT_FINDINGS


def test_json_output_and_min_severity(capsys):
    main([str(FIXTURES / "escalation.json"), "--format", "json", "--min-severity", "high"])
    data = json.loads(capsys.readouterr().out)
    assert {d["rule_id"] for d in data} == {"IAM008", "IAM009"}
    assert all(d["severity"] in ("HIGH", "CRITICAL") for d in data)
    assert all(d["source"].endswith("escalation.json") for d in data)


def test_multiple_files(capsys):
    main([str(FIXTURES / "admin.json"), str(FIXTURES / "least_privilege.json")])
    out = capsys.readouterr().out
    assert "admin.json: 1 finding(s)" in out
    assert "least_privilege.json: 0 finding(s)" in out


def test_reads_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO((FIXTURES / "admin.json").read_text()))
    assert main(["-"]) == EXIT_FINDINGS
    assert "<stdin>: 1 finding(s)" in capsys.readouterr().out


def test_invalid_file_exits_two(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    assert main([str(bad)]) == EXIT_ERROR
    assert "Invalid JSON" in capsys.readouterr().err


def test_missing_file_exits_two(tmp_path):
    assert main([str(tmp_path / "missing.json")]) == EXIT_ERROR
