"""Command-line entry point: ``python -m cloudtrail_analyzer`` or ``cloudtrail-analyzer``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .analyzer import analyze
from .loader import LogLoadError, load_events
from .models import Severity
from .report import RENDERERS, render_text
from .rules import ALL_RULES, Config


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudtrail-analyzer",
        description="Scan AWS CloudTrail logs for suspicious activity.",
    )
    parser.add_argument("paths", nargs="*", help="log files or directories to scan")
    parser.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text",
                        help="output format (default: text)")
    parser.add_argument("-o", "--output", help="write the report to this file instead of stdout")
    parser.add_argument("--min-severity", type=_severity, default=Severity.LOW,
                        help="hide findings below this level: low, medium, high, critical")
    parser.add_argument("--fail-on", type=_severity, metavar="SEVERITY",
                        help="exit with status 1 if any finding is at or above this level")
    parser.add_argument("--allowed-regions", metavar="REGIONS",
                        help="comma-separated regions you expect activity in; enables CT-013")
    parser.add_argument("--failed-login-threshold", type=_positive_int,
                        default=Config.failed_login_threshold)
    parser.add_argument("--access-denied-threshold", type=_positive_int,
                        default=Config.access_denied_threshold)
    parser.add_argument("--window-minutes", type=_positive_int, default=Config.window_minutes,
                        help="sliding window used by the threshold rules (default: 15)")
    parser.add_argument("--list-rules", action="store_true", help="list detection rules and exit")
    parser.add_argument("--no-color", action="store_true", help="disable colored text output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def list_rules() -> str:
    lines = []
    for rule in ALL_RULES:
        lines.append(f"{rule.rule_id}  {rule.severity.name:<8}  {rule.title}  "
                     f"[{', '.join(rule.mitre)}]")
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        sys.stdout.write(list_rules())
        return 0
    if not args.paths:
        parser.error("at least one log file or directory is required")

    try:
        events = load_events(args.paths)
    except LogLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    allowed = None
    if args.allowed_regions:
        allowed = frozenset(r.strip() for r in args.allowed_regions.split(",") if r.strip())
    config = Config(
        failed_login_threshold=args.failed_login_threshold,
        access_denied_threshold=args.access_denied_threshold,
        window_minutes=args.window_minutes,
        allowed_regions=allowed,
    )
    findings = analyze(events, config, min_severity=args.min_severity)

    if args.format == "text":
        use_color = not args.no_color and not args.output and sys.stdout.isatty()
        report = render_text(findings, events, color=use_color)
    else:
        report = RENDERERS[args.format](findings, events)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in findings):
        return 1
    return 0
