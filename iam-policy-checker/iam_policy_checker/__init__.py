"""Review AWS IAM policy documents for risky permissions."""

from .checker import Finding, Severity, check_policy
from .policy import Policy, PolicyError, load_policy, parse_policy

__all__ = [
    "Finding",
    "Policy",
    "PolicyError",
    "Severity",
    "check_policy",
    "load_policy",
    "parse_policy",
]

__version__ = "0.1.0"
