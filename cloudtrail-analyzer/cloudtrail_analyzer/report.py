"""Render findings as a terminal report, JSON or Markdown."""

from __future__ import annotations

import json
from collections import Counter

from .models import Event, Finding, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;41;97m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def _summary_counts(findings: list[Finding]) -> Counter[Severity]:
    return Counter(f.severity for f in findings)


def _fmt_time(finding: Finding) -> str:
    return finding.time.strftime("%Y-%m-%d %H:%M:%SZ") if finding.time else "-"


def _fmt_details(finding: Finding) -> str:
    parts = []
    for key, value in finding.details.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            value = ", ".join(map(str, value))
        parts.append(f"{key}={value}")
    return "; ".join(parts)


def render_text(findings: list[Finding], events: list[Event], color: bool = False) -> str:
    counts = _summary_counts(findings)
    lines = [
        f"Analyzed {len(events)} events, {len(findings)} findings "
        + "("
        + ", ".join(f"{counts[s]} {s.name.lower()}" for s in sorted(Severity, reverse=True))
        + ")",
        "",
    ]
    if not findings:
        lines.append("No suspicious activity found.")
        return "\n".join(lines) + "\n"

    for f in findings:
        label = f"[{f.severity.name}]"
        if color:
            label = f"{_COLORS[f.severity]}{label}{_RESET}"
        lines.append(f"{label} {f.rule_id} {f.title}")
        lines.append(f"    when:   {_fmt_time(f)}   region: {f.region or '-'}")
        lines.append(f"    who:    {f.actor}   from: {f.source_ip or '-'}")
        details = _fmt_details(f)
        if details:
            lines.append(f"    detail: {details}")
        if f.mitre:
            lines.append(f"    mitre:  {', '.join(f.mitre)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(findings: list[Finding], events: list[Event]) -> str:
    counts = _summary_counts(findings)
    payload = {
        "events_analyzed": len(events),
        "summary": {s.name: counts[s] for s in sorted(Severity, reverse=True)},
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2) + "\n"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(findings: list[Finding], events: list[Event]) -> str:
    counts = _summary_counts(findings)
    lines = [
        "# CloudTrail analysis report",
        "",
        f"**Events analyzed:** {len(events)}  ",
        f"**Findings:** {len(findings)}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {s.name} | {counts[s]} |" for s in sorted(Severity, reverse=True)]
    lines += [
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No suspicious activity found.")
        return "\n".join(lines) + "\n"
    lines += [
        "| Severity | Rule | Title | Time (UTC) | Actor | Source IP | Region | MITRE ATT&CK |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            "| "
            + " | ".join(
                _md_escape(str(v))
                for v in (
                    f.severity.name, f.rule_id, f.title, _fmt_time(f), f.actor,
                    f.source_ip or "-", f.region or "-", ", ".join(f.mitre),
                )
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}
