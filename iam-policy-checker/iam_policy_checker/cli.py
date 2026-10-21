"""Command-line interface: ``iam-policy-checker policy.json [...]``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import Finding, Severity, check_policy
from .policy import PolicyError, load_policy

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _format_text(findings: list[Finding], sources: list[str]) -> str:
    lines = []
    for source in sources:
        own = [f for f in findings if f.source == source]
        lines.append(f"{source}: {len(own)} finding(s)")
        for f in own:
            where = ", ".join(f"Statement[{i}]" for i in f.statements) or "policy"
            lines.append(f"  [{f.severity.name}] {f.rule_id} {f.title} ({where})")
            lines.append(f"      {f.detail}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-policy-checker",
        description="Review AWS IAM policy JSON for risky permissions.",
    )
    parser.add_argument("policies", nargs="+", help="policy JSON files, or - for stdin")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--min-severity",
        default="low",
        type=str.lower,
        choices=[s.name.lower() for s in Severity],
        help="hide findings below this severity (default: low)",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        type=str.lower,
        choices=[s.name.lower() for s in Severity] + ["none"],
        help="exit with status 1 if any finding is at or above this severity (default: high)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    min_severity = Severity.parse(args.min_severity)

    findings: list[Finding] = []
    sources: list[str] = []
    for path in args.policies:
        source = "<stdin>" if path == "-" else path
        try:
            policy = load_policy(_read(path), source=source)
        except (OSError, PolicyError) as exc:
            print(f"error: {source}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        sources.append(source)
        findings.extend(f for f in check_policy(policy) if f.severity >= min_severity)

    if args.format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        print(_format_text(findings, sources))

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK
