"""Run the full pipeline and CLI against the bundled sample logs."""

from __future__ import annotations

import json
from collections import Counter

from cloudtrail_analyzer import Config, Severity, analyze, load_events
from cloudtrail_analyzer.cli import main


def test_benign_sample_has_nothing_above_low(samples_dir):
    events = load_events([samples_dir / "benign_activity.json"])
    findings = analyze(events, min_severity=Severity.MEDIUM)
    assert findings == []
    # The only low-severity note is the intentionally public HTTPS load balancer.
    assert [f.rule_id for f in analyze(events)] == ["CT-010"]


def test_attack_sample_triggers_every_rule(samples_dir):
    events = load_events([samples_dir / "compromised_credentials.json"])
    config = Config(allowed_regions=frozenset({"us-east-1", "us-west-2"}))
    findings = analyze(events, config)
    fired = {f.rule_id for f in findings}
    assert fired == {f"CT-{i:03d}" for i in range(1, 14)}


def test_findings_are_sorted_most_severe_first(samples_dir):
    findings = analyze(load_events([samples_dir]))
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, reverse=True)
    assert findings[0].rule_id == "CT-007"


def test_cli_json_output(samples_dir, capsys):
    code = main([str(samples_dir), "--format", "json", "--min-severity", "high"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events_analyzed"] > 0
    assert all(f["severity"] in ("HIGH", "CRITICAL") for f in payload["findings"])
    assert payload["summary"]["CRITICAL"] == 1
    assert payload["summary"]["MEDIUM"] == 0


def test_cli_fail_on_sets_exit_code(samples_dir, capsys):
    assert main([str(samples_dir / "compromised_credentials.json"), "--fail-on", "critical"]) == 1
    assert main([str(samples_dir / "benign_activity.json"), "--fail-on", "medium"]) == 0


def test_cli_text_and_markdown(samples_dir, capsys, tmp_path):
    main([str(samples_dir / "compromised_credentials.json"), "--no-color"])
    text = capsys.readouterr().out
    assert "[CRITICAL] CT-007 CloudTrail logging disabled or changed" in text
    assert "\033[" not in text

    out = tmp_path / "report.md"
    main([str(samples_dir), "-f", "markdown", "-o", str(out)])
    md = out.read_text()
    assert md.startswith("# CloudTrail analysis report")
    assert md.count("| CT-") == len(analyze(load_events([samples_dir])))


def test_cli_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 13
    assert Counter(line.split()[0][:3] for line in lines) == {"CT-": 13}


def test_cli_reports_load_errors(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert main([str(bad)]) == 2
    assert "error:" in capsys.readouterr().err


def test_cli_region_rule(samples_dir, capsys):
    main([str(samples_dir), "-f", "json", "--allowed-regions", "us-east-1"])
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert "CT-013" in rules
