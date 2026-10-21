"""Rules that flag risky permissions in an IAM policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum

from .escalation import ESCALATION_PATHS
from .policy import Policy, Statement


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, name: str) -> "Severity":
        try:
            return cls[name.upper()]
        except KeyError:
            raise ValueError(f"Unknown severity {name!r}") from None


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    statements: list[int]
    source: str = "<policy>"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["severity"] = self.severity.name
        return data


# Services where broad access is usually equivalent to (or a step from) admin.
SENSITIVE_SERVICES = {
    "iam",
    "sts",
    "organizations",
    "kms",
    "secretsmanager",
    "cloudtrail",
    "config",
    "guardduty",
    "account",
}

# Actions that read secrets or decrypt data; granting them on "*" is a data-exposure risk.
SENSITIVE_DATA_ACTIONS = [
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "ssm:GetParametersByPath",
    "kms:Decrypt",
    "s3:GetObject",
]

READ_ONLY_PREFIXES = ("get", "list", "describe", "head", "view", "search", "lookup", "batchget", "scan", "query")

RECOMMENDED_VERSION = "2012-10-17"


def _service(action: str) -> str:
    return action.split(":", 1)[0].lower() if ":" in action else ""


def _action_name(action: str) -> str:
    return action.split(":", 1)[1] if ":" in action else action


def _is_read_only(action: str) -> bool:
    name = _action_name(action).lower()
    return "*" not in name and "?" not in name and name.startswith(READ_ONLY_PREFIXES)


def _is_full_admin(stmt: Statement) -> bool:
    return stmt.is_allow and "*" in stmt.actions and stmt.all_resources


def _denied(policy: Policy, action: str) -> bool:
    """True if an unconditional Deny on every resource blocks the action."""
    return any(
        s.matches_action(action) and s.all_resources and not s.condition
        for s in policy.deny_statements
    )


def _granting_statements(policy: Policy, action: str) -> list[Statement]:
    if _denied(policy, action):
        return []
    return [s for s in policy.allow_statements if s.matches_action(action)]


class Checker:
    """Runs every rule against a policy and collects findings."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.findings: list[Finding] = []
        self.has_full_admin = any(_is_full_admin(s) for s in policy.statements)

    def _add(self, rule_id, severity, title, detail, statements):
        self.findings.append(
            Finding(rule_id, severity, title, detail, sorted(statements), self.policy.source)
        )

    def run(self) -> list[Finding]:
        self._check_version()
        for stmt in self.policy.allow_statements:
            self._check_statement(stmt)
        self._check_escalation_paths()
        self._check_sensitive_data()
        self.findings.sort(key=lambda f: (-f.severity, f.rule_id, f.statements))
        return self.findings

    def _check_version(self):
        version = self.policy.version
        if version != RECOMMENDED_VERSION:
            self._add(
                "IAM012",
                Severity.LOW,
                "Missing or outdated policy Version",
                f"Version is {version!r}; use {RECOMMENDED_VERSION!r} so policy variables "
                "such as ${aws:username} are evaluated instead of treated as literals.",
                [],
            )

    def _check_statement(self, stmt: Statement):
        label = stmt.label

        if stmt.has_principal and "*" in stmt.principals:
            if stmt.condition:
                self._add(
                    "IAM010",
                    Severity.MEDIUM,
                    "Public principal restricted only by a Condition",
                    f"{label} allows Principal '*'. Confirm the Condition keys really limit "
                    "who can use it (for example aws:PrincipalOrgID or aws:SourceArn).",
                    [stmt.index],
                )
            else:
                self._add(
                    "IAM010",
                    Severity.CRITICAL,
                    "Resource is open to any AWS principal",
                    f"{label} allows Principal '*' with no Condition, so anyone, "
                    "including anonymous or other-account callers, gets these actions.",
                    [stmt.index],
                )

        if _is_full_admin(stmt):
            self._add(
                "IAM001",
                Severity.CRITICAL,
                "Full administrator access",
                f"{label} allows Action '*' on Resource '*', which grants every permission "
                "in the account.",
                [stmt.index],
            )
            return

        if stmt.not_actions:
            self._add(
                "IAM005",
                Severity.HIGH,
                "Allow with NotAction",
                f"{label} allows every action except {', '.join(stmt.not_actions)}. "
                "This grants new and unrelated services by default; list the actions "
                "that are needed instead.",
                [stmt.index],
            )
        if stmt.not_resources:
            self._add(
                "IAM006",
                Severity.MEDIUM,
                "Allow with NotResource",
                f"{label} applies to every resource except {', '.join(stmt.not_resources)}, "
                "including resources created later.",
                [stmt.index],
            )

        if "*" in stmt.actions:
            self._add(
                "IAM002",
                Severity.HIGH,
                "Wildcard action",
                f"{label} allows Action '*' (every action in every service) on "
                f"{', '.join(stmt.resources)}.",
                [stmt.index],
            )

        for action in stmt.actions:
            if action == "*" or ":" not in action:
                continue
            service, name = _service(action), _action_name(action)
            if name == "*":
                severity = Severity.HIGH if service in SENSITIVE_SERVICES else Severity.MEDIUM
                self._add(
                    "IAM003",
                    severity,
                    "Service-wide wildcard action",
                    f"{label} allows {action}, every current and future action in "
                    f"the {service} service.",
                    [stmt.index],
                )
            elif ("*" in name or "?" in name) and service in SENSITIVE_SERVICES:
                self._add(
                    "IAM004",
                    Severity.LOW,
                    "Partial wildcard in a sensitive service",
                    f"{label} allows {action}. Wildcards in {service} can match more "
                    "actions than intended; prefer explicit action names.",
                    [stmt.index],
                )

        if "*" in stmt.resources and "*" not in stmt.actions and not stmt.not_actions:
            writes = [a for a in stmt.actions if not _is_read_only(a)]
            if writes:
                self._add(
                    "IAM007",
                    Severity.MEDIUM,
                    "Write access on all resources",
                    f"{label} allows {', '.join(writes)} on Resource '*'. Scope it to "
                    "specific ARNs where the service supports it.",
                    [stmt.index],
                )

        if stmt.all_resources and stmt.matches_action("iam:PassRole") and not _denied(
            self.policy, "iam:PassRole"
        ):
            self._add(
                "IAM008",
                Severity.HIGH,
                "iam:PassRole on all roles",
                f"{label} lets the caller pass any role, including admin roles, to "
                "services such as EC2 or Lambda. Restrict Resource to specific role ARNs "
                "and add an iam:PassedToService condition.",
                [stmt.index],
            )

    def _check_escalation_paths(self):
        # Full admin already implies every escalation path; repeating them is noise.
        if self.has_full_admin:
            return
        for path in ESCALATION_PATHS:
            grants = {action: _granting_statements(self.policy, action) for action in path.actions}
            if not all(grants.values()):
                continue

            # Severity depends on the broadest statement granting each action.
            def broadest(stmts: list[Statement]) -> Severity:
                if any(s.all_resources and not s.condition for s in stmts):
                    return Severity.CRITICAL
                if any(s.all_resources for s in stmts):
                    return Severity.HIGH
                return Severity.MEDIUM

            severity = min(broadest(stmts) for stmts in grants.values())
            indexes = {s.index for stmts in grants.values() for s in stmts}
            note = ""
            if severity < Severity.CRITICAL:
                note = (
                    " Some of these actions are limited by resource ARNs or conditions; "
                    "check that those limits really prevent the escalation."
                )
            self._add(
                "IAM009",
                severity,
                f"Privilege escalation: {path.name}",
                f"Allows {' + '.join(path.actions)}. {path.description}{note}",
                indexes,
            )

    def _check_sensitive_data(self):
        if self.has_full_admin:
            return
        for action in SENSITIVE_DATA_ACTIONS:
            stmts = [s for s in _granting_statements(self.policy, action) if s.all_resources]
            # Service-wide or global wildcards are already reported by IAM002/IAM003.
            stmts = [
                s
                for s in stmts
                if not s.not_actions
                and not any(a == "*" or a.lower() == f"{_service(action)}:*" for a in s.actions)
            ]
            if stmts:
                self._add(
                    "IAM011",
                    Severity.MEDIUM,
                    "Sensitive data access on all resources",
                    f"{action} is allowed on every resource. Scope it to the specific "
                    "secrets, parameters, keys or buckets the workload needs.",
                    [s.index for s in stmts],
                )


def check_policy(policy: Policy) -> list[Finding]:
    """Return findings for a parsed policy, most severe first."""
    return Checker(policy).run()
