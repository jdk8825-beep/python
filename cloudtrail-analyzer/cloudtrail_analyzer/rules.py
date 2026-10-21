"""Detection rules.

Each rule looks at the full, time-sorted list of events and returns findings.
Rules come in two shapes:

* ``EventRule``: judges one event at a time (e.g. "someone called StopLogging").
* ``ThresholdRule``: counts matching events per key inside a sliding time
  window (e.g. "5 failed console logins from one IP within 15 minutes").

To add a rule, subclass one of these, fill in the class attributes, and add
the class to ``ALL_RULES`` at the bottom of this file.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import unquote

from .models import Event, Finding, Severity


@dataclass
class Config:
    """Tunable thresholds. Defaults are a reasonable starting point."""

    failed_login_threshold: int = 5
    access_denied_threshold: int = 10
    window_minutes: int = 15
    allowed_regions: frozenset[str] | None = None

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.window_minutes)


class Rule:
    rule_id: str = ""
    title: str = ""
    severity: Severity = Severity.LOW
    mitre: tuple[str, ...] = ()
    description: str = ""

    def evaluate(self, events: list[Event], config: Config) -> list[Finding]:
        raise NotImplementedError


class EventRule(Rule):
    """A rule that inspects events one at a time.

    Subclasses implement ``check``, returning ``None`` for "not suspicious" or
    a dict of details to attach to the finding. A call that AWS rejected
    (``errorCode`` set) is still reported, since a failed attempt to disable
    logging is worth knowing about, but one severity level lower.
    """

    #: Event names this rule cares about. Empty means "look at every event".
    event_names: frozenset[str] = frozenset()

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        raise NotImplementedError

    def severity_for(self, event: Event, details: dict[str, Any]) -> Severity:
        return self.severity

    def evaluate(self, events: list[Event], config: Config) -> list[Finding]:
        findings = []
        for event in events:
            if self.event_names and event.name not in self.event_names:
                continue
            details = self.check(event, config)
            if details is None:
                continue
            severity = self.severity_for(event, details)
            title = self.title
            if event.error_code:
                severity = Severity(max(Severity.LOW, severity - 1))
                title = f"{title} (attempt failed: {event.error_code})"
            findings.append(
                Finding.from_event(
                    event,
                    rule_id=self.rule_id,
                    title=title,
                    severity=severity,
                    description=self.description,
                    mitre=list(self.mitre),
                    details={"eventName": event.name, **details},
                )
            )
        return findings


class ThresholdRule(Rule):
    """A rule that fires when too many matching events share a key in a window."""

    def matches(self, event: Event) -> bool:
        raise NotImplementedError

    def key(self, event: Event) -> str:
        raise NotImplementedError

    def threshold(self, config: Config) -> int:
        raise NotImplementedError

    def evaluate(self, events: list[Event], config: Config) -> list[Finding]:
        groups: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.time is not None and self.matches(event):
                groups[self.key(event)].append(event)

        limit = self.threshold(config)
        findings = []
        for key, group in groups.items():
            group.sort(key=lambda e: e.time)
            burst = _densest_window(group, config.window)
            if len(burst) < limit:
                continue
            first, last = burst[0], burst[-1]
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=self.severity,
                    description=self.description,
                    actor=last.actor,
                    source_ip=last.source_ip,
                    region=last.region,
                    time=first.time,
                    event_ids=[e.event_id for e in burst if e.event_id],
                    mitre=list(self.mitre),
                    details={
                        "key": key,
                        "count_in_window": len(burst),
                        "total_matching": len(group),
                        "window_minutes": config.window_minutes,
                        "window_start": first.time.isoformat(),
                        "window_end": last.time.isoformat(),
                        "event_names": sorted({e.name for e in burst}),
                    },
                )
            )
        return findings


def _densest_window(events: list[Event], window: timedelta) -> list[Event]:
    """Return the largest run of time-sorted ``events`` that fits in ``window``."""
    best_start, best_end, start = 0, 0, 0
    for end in range(len(events)):
        while events[end].time - events[start].time > window:
            start += 1
        if end + 1 - start > best_end - best_start:
            best_start, best_end = start, end + 1
    return events[best_start:best_end]


def _walk(value: Any) -> Iterator[tuple[str, Any]]:
    """Yield every (key, value) pair in a nested dict/list structure."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _parse_policy(document: Any) -> dict[str, Any]:
    """IAM and S3 policy documents arrive as (sometimes URL-encoded) JSON strings."""
    if isinstance(document, dict):
        return document
    if not isinstance(document, str):
        return {}
    for candidate in (document, unquote(document)):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _allow_statements(policy: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for statement in _as_list(policy.get("Statement")):
        if isinstance(statement, dict) and statement.get("Effect") == "Allow":
            yield statement


# --------------------------------------------------------------------------
# Identity and access
# --------------------------------------------------------------------------


class RootAccountUsage(EventRule):
    rule_id = "CT-001"
    title = "Root account used"
    severity = Severity.HIGH
    mitre = ("T1078.004",)
    description = (
        "The root user has unrestricted access to the account and should only be "
        "used for the handful of tasks that require it. Day-to-day use is a red flag."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        if event.identity_type != "Root":
            return None
        # Calls AWS services make on the account's behalf are not root logins.
        if event.identity.get("invokedBy") or event.raw.get("eventType") == "AwsServiceEvent":
            return None
        return {"eventSource": event.source}


class ConsoleLoginWithoutMFA(EventRule):
    rule_id = "CT-002"
    title = "Console login without MFA"
    severity = Severity.MEDIUM
    mitre = ("T1078.004",)
    event_names = frozenset({"ConsoleLogin"})
    description = (
        "A successful AWS console sign-in did not use multi-factor authentication, "
        "so a stolen password alone was enough to get in."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        if event.response.get("ConsoleLogin") != "Success":
            return None
        if event.additional.get("MFAUsed") != "No":
            return None
        # Federated (SSO) sign-ins enforce MFA at the identity provider instead.
        if event.identity_type in ("AssumedRole", "FederatedUser"):
            return None
        return {"identityType": event.identity_type}

    def severity_for(self, event: Event, details: dict[str, Any]) -> Severity:
        return Severity.CRITICAL if event.identity_type == "Root" else self.severity


class BruteForceConsoleLogin(ThresholdRule):
    rule_id = "CT-003"
    title = "Repeated failed console logins"
    severity = Severity.HIGH
    mitre = ("T1110",)
    description = (
        "Many console sign-ins failed from one source IP in a short time, which "
        "looks like password guessing or credential stuffing."
    )

    def matches(self, event: Event) -> bool:
        return event.name == "ConsoleLogin" and event.response.get("ConsoleLogin") == "Failure"

    def key(self, event: Event) -> str:
        return event.source_ip or "unknown"

    def threshold(self, config: Config) -> int:
        return config.failed_login_threshold


IAM_PERSISTENCE_EVENTS = frozenset(
    {"CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"}
)


class IAMPersistence(EventRule):
    rule_id = "CT-004"
    title = "New IAM user or credentials created"
    severity = Severity.MEDIUM
    mitre = ("T1136.003", "T1098.001")
    event_names = IAM_PERSISTENCE_EVENTS
    description = (
        "New IAM users, access keys and console passwords are a common way for an "
        "attacker to keep access after the original credentials are revoked."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        target = event.request.get("userName") or event.actor
        details: dict[str, Any] = {"targetUser": target}
        # Creating keys for *someone else* is more suspicious than for yourself.
        details["forOtherUser"] = target != event.actor
        return details

    def severity_for(self, event: Event, details: dict[str, Any]) -> Severity:
        if event.name == "CreateAccessKey" and details["forOtherUser"]:
            return Severity.HIGH
        return self.severity


ATTACH_POLICY_EVENTS = frozenset({"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"})
INLINE_POLICY_EVENTS = frozenset({"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"})
ADMIN_POLICY_ARNS = frozenset(
    {"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/IAMFullAccess"}
)


class AdminPolicyGranted(EventRule):
    rule_id = "CT-005"
    title = "Administrator permissions granted"
    severity = Severity.HIGH
    mitre = ("T1098.003", "T1484")
    event_names = ATTACH_POLICY_EVENTS | INLINE_POLICY_EVENTS
    description = (
        "A user, role or group was given administrator-level permissions, either by "
        "attaching a managed admin policy or with an inline policy allowing '*' on '*'."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        req = event.request
        target = req.get("userName") or req.get("roleName") or req.get("groupName")
        if event.name in ATTACH_POLICY_EVENTS:
            arn = req.get("policyArn", "")
            if arn in ADMIN_POLICY_ARNS:
                return {"target": target, "policyArn": arn}
            return None
        policy = _parse_policy(req.get("policyDocument"))
        for statement in _allow_statements(policy):
            if "*" in _as_list(statement.get("Action")) and "*" in _as_list(
                statement.get("Resource")
            ):
                return {"target": target, "policyName": req.get("policyName")}
        return None


class AccessDeniedBurst(ThresholdRule):
    rule_id = "CT-006"
    title = "Burst of access-denied errors"
    severity = Severity.MEDIUM
    mitre = ("T1580", "T1087.004")
    description = (
        "One principal hit many authorization errors in a short time. This is typical "
        "of someone enumerating what a stolen credential is allowed to do."
    )
    error_codes = frozenset(
        {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
         "Client.UnauthorizedOperation", "UnauthorizedAccess"}
    )

    def matches(self, event: Event) -> bool:
        return event.error_code in self.error_codes

    def key(self, event: Event) -> str:
        return event.identity.get("arn") or event.actor

    def threshold(self, config: Config) -> int:
        return config.access_denied_threshold


# --------------------------------------------------------------------------
# Defense evasion
# --------------------------------------------------------------------------


class CloudTrailTampering(EventRule):
    rule_id = "CT-007"
    title = "CloudTrail logging disabled or changed"
    severity = Severity.CRITICAL
    mitre = ("T1562.008",)
    event_names = frozenset(
        {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
         "DeleteEventDataStore", "StopEventDataStoreIngestion"}
    )
    description = (
        "Someone stopped, deleted or reconfigured CloudTrail. Attackers do this to "
        "hide what they do next."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        trail = event.request.get("name") or event.request.get("trailName")
        return {"trail": trail}

    def severity_for(self, event: Event, details: dict[str, Any]) -> Severity:
        # Changing event selectors or trail settings can be routine admin work.
        if event.name in ("UpdateTrail", "PutEventSelectors"):
            return Severity.HIGH
        return self.severity


class SecurityMonitoringDisabled(EventRule):
    rule_id = "CT-008"
    title = "Security monitoring disabled"
    severity = Severity.HIGH
    mitre = ("T1562.001",)
    event_names = frozenset(
        {"DeleteDetector", "DisassociateFromMasterAccount", "StopMonitoringMembers",
         "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel",
         "DeleteFlowLogs", "DisableSecurityHub", "DeleteAnalyzer"}
    )
    description = (
        "A security service (GuardDuty, AWS Config, VPC Flow Logs, Security Hub or "
        "IAM Access Analyzer) was switched off or deleted."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        return {"eventSource": event.source}


class KMSKeyDeletion(EventRule):
    rule_id = "CT-009"
    title = "KMS key disabled or scheduled for deletion"
    severity = Severity.HIGH
    mitre = ("T1485", "T1486")
    event_names = frozenset({"ScheduleKeyDeletion", "DisableKey"})
    description = (
        "Deleting or disabling a KMS key makes everything encrypted with it unreadable. "
        "It can be sabotage or part of a ransom attempt."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        return {
            "keyId": event.request.get("keyId"),
            "pendingWindowInDays": event.request.get("pendingWindowInDays"),
        }


# --------------------------------------------------------------------------
# Exposure and exfiltration
# --------------------------------------------------------------------------

OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
                   6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}
WEB_PORTS = frozenset({80, 443})


class SecurityGroupOpenToWorld(EventRule):
    rule_id = "CT-010"
    title = "Security group opened to the internet"
    severity = Severity.MEDIUM
    mitre = ("T1562.007",)
    event_names = frozenset({"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"})
    description = (
        "An inbound rule now allows traffic from anywhere (0.0.0.0/0 or ::/0). "
        "Sensitive ports such as SSH, RDP or databases are raised to HIGH; rules "
        "that only open web ports (80/443) are lowered to LOW."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        req = event.request
        open_rules = [p for p in _iter_permissions(req) if _is_open(p)]
        if not open_rules:
            return None
        ports: set[int] = set()
        for rule in open_rules:
            ports.update(_sensitive_ports(rule))
        return {
            "groupId": req.get("groupId"),
            "sensitivePorts": sorted(f"{p}/{SENSITIVE_PORTS[p]}" for p in ports),
            "webOnly": all(_is_web_only(rule) for rule in open_rules),
        }

    def severity_for(self, event: Event, details: dict[str, Any]) -> Severity:
        if details["sensitivePorts"]:
            return Severity.HIGH
        if details["webOnly"]:
            return Severity.LOW
        return self.severity


def _lower_keys(d: dict[str, Any]) -> dict[str, Any]:
    return {k.lower(): v for k, v in d.items()}


def _iter_permissions(req: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield individual inbound rules from the request formats EC2 logs.

    * classic: ``ipPermissions.items[]`` with ``ipRanges.items[].cidrIp``
    * flat: ``cidrIp``/``fromPort``/``toPort`` directly on the request
    * ModifySecurityGroupRules: ``...SecurityGroupRule`` with ``CidrIpv4``
    """
    items = (req.get("ipPermissions") or {}).get("items")
    for item in _as_list(items):
        if isinstance(item, dict):
            yield item
    for key, value in _walk(req):
        if key.lower() == "securitygrouprule" and isinstance(value, dict):
            yield value
    if "cidrIp" in req or "cidrIpv6" in req:
        yield req


def _is_open(permission: dict[str, Any]) -> bool:
    return any(
        k.lower() in ("cidrip", "cidripv4", "cidripv6") and v in OPEN_CIDRS
        for k, v in _walk(permission)
    )


def _is_web_only(permission: dict[str, Any]) -> bool:
    p = _lower_keys(permission)
    low, high = p.get("fromport"), p.get("toport")
    return str(p.get("ipprotocol")) == "tcp" and low == high and low in WEB_PORTS


def _sensitive_ports(permission: dict[str, Any]) -> set[int]:
    p = _lower_keys(permission)
    if str(p.get("ipprotocol")) == "-1":  # all traffic
        return set(SENSITIVE_PORTS)
    low, high = p.get("fromport"), p.get("toport")
    if not isinstance(low, int) or not isinstance(high, int):
        return set()
    return {port for port in SENSITIVE_PORTS if low <= port <= high}


PUBLIC_GRANTEE_URIS = frozenset(
    {"http://acs.amazonaws.com/groups/global/AllUsers",
     "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}
)


class S3BucketMadePublic(EventRule):
    rule_id = "CT-011"
    title = "S3 bucket made public"
    severity = Severity.HIGH
    mitre = ("T1530",)
    event_names = frozenset(
        {"PutBucketAcl", "PutObjectAcl", "PutBucketPolicy",
         "DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock",
         "PutBucketPublicAccessBlock", "PutPublicAccessBlock"}
    )
    description = (
        "A bucket ACL or policy now grants access to everyone, or the S3 Block Public "
        "Access safety net was removed."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        req = event.request
        bucket = req.get("bucketName")
        if event.name in ("PutBucketAcl", "PutObjectAcl"):
            for _, value in _walk(req):
                if isinstance(value, str) and value in PUBLIC_GRANTEE_URIS:
                    return {"bucket": bucket, "grantee": value}
            return None
        if event.name == "PutBucketPolicy":
            policy = _parse_policy(req.get("bucketPolicy") or req.get("policy"))
            for statement in _allow_statements(policy):
                principal = statement.get("Principal")
                if principal == "*" or (
                    isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))
                ):
                    if not statement.get("Condition"):
                        return {"bucket": bucket, "principal": "*"}
            return None
        if event.name.startswith("Delete"):
            return {"bucket": bucket, "change": "Block Public Access removed"}
        # Put*PublicAccessBlock: only suspicious when it turns protections off.
        settings = next(
            (v for k, v in _walk(req) if k == "PublicAccessBlockConfiguration"
             and isinstance(v, dict)), {}
        )
        disabled = sorted(k for k, v in settings.items() if v is False)
        if disabled:
            return {"bucket": bucket, "disabledSettings": disabled}
        return None


class PublicSnapshot(EventRule):
    rule_id = "CT-012"
    title = "Snapshot or AMI shared publicly"
    severity = Severity.HIGH
    mitre = ("T1537",)
    event_names = frozenset({"ModifySnapshotAttribute", "ModifyImageAttribute",
                             "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"})
    description = (
        "A disk snapshot, machine image or database snapshot was shared with all AWS "
        "accounts. Anyone could copy the data out."
    )

    def check(self, event: Event, config: Config) -> dict[str, Any] | None:
        req = event.request
        # EC2: createVolumePermission/launchPermission -> add -> items -> [{"group": "all"}]
        for key in ("createVolumePermission", "launchPermission"):
            adds = ((req.get(key) or {}).get("add") or {}).get("items")
            if any(isinstance(i, dict) and i.get("group") == "all" for i in _as_list(adds)):
                return {"resource": req.get("snapshotId") or req.get("imageId")}
        # RDS: valuesToAdd contains "all"
        if "all" in _as_list(req.get("valuesToAdd")):
            return {"resource": req.get("dBSnapshotIdentifier")
                    or req.get("dBClusterSnapshotIdentifier")}
        return None


class UnapprovedRegion(EventRule):
    rule_id = "CT-013"
    title = "Activity in an unapproved region"
    severity = Severity.MEDIUM
    mitre = ("T1535",)
    description = (
        "API calls were made in a region your organization does not use. Attackers "
        "often launch resources (e.g. crypto miners) where nobody is looking."
    )

    def evaluate(self, events: list[Event], config: Config) -> list[Finding]:
        # Only meaningful when the user tells us which regions are expected.
        if not config.allowed_regions:
            return []
        # One finding per (actor, region) keeps the report readable.
        seen: dict[tuple[str, str], Finding] = {}
        for event in events:
            region = event.region
            if not region or region in config.allowed_regions:
                continue
            if event.raw.get("eventType") == "AwsServiceEvent" or event.identity.get("invokedBy"):
                continue
            key = (event.actor, region)
            if key in seen:
                seen[key].event_ids.append(event.event_id)
                seen[key].details["count"] += 1
                continue
            seen[key] = Finding.from_event(
                event,
                rule_id=self.rule_id,
                title=f"{self.title}: {region}",
                severity=self.severity,
                description=self.description,
                mitre=list(self.mitre),
                details={"region": region, "count": 1, "firstEvent": event.name},
            )
        return list(seen.values())


ALL_RULES: tuple[type[Rule], ...] = (
    RootAccountUsage,
    ConsoleLoginWithoutMFA,
    BruteForceConsoleLogin,
    IAMPersistence,
    AdminPolicyGranted,
    AccessDeniedBurst,
    CloudTrailTampering,
    SecurityMonitoringDisabled,
    KMSKeyDeletion,
    SecurityGroupOpenToWorld,
    S3BucketMadePublic,
    PublicSnapshot,
    UnapprovedRegion,
)
