"""Run a set of rules over events and collect the findings."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from .models import Event, Finding, Severity
from .rules import ALL_RULES, Config, Rule

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def analyze(
    events: list[Event],
    config: Config | None = None,
    rules: Iterable[type[Rule]] = ALL_RULES,
    min_severity: Severity = Severity.LOW,
) -> list[Finding]:
    """Return findings at or above ``min_severity``, most severe first, then by time."""
    config = config or Config()
    findings: list[Finding] = []
    for rule_cls in rules:
        findings.extend(rule_cls().evaluate(events, config))
    findings = [f for f in findings if f.severity >= min_severity]
    findings.sort(key=lambda f: (-f.severity, f.time or _EPOCH, f.rule_id))
    return findings
