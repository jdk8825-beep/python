"""Find suspicious activity in AWS CloudTrail logs."""

from .analyzer import analyze
from .loader import load_events
from .models import Event, Finding, Severity
from .rules import ALL_RULES, Config

__all__ = ["ALL_RULES", "Config", "Event", "Finding", "Severity", "analyze", "load_events"]
__version__ = "0.1.0"
