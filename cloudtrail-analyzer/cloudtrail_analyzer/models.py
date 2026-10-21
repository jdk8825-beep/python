"""Core data types shared by the loader, the rules and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity. Integer values make severities sortable and comparable."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from None

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Event:
    """A thin, read-only wrapper around one raw CloudTrail record.

    CloudTrail records are deeply nested and many fields are optional, so the
    accessors here never raise on missing data; they return ``None`` or ``""``.
    """

    raw: dict[str, Any]

    @property
    def name(self) -> str:
        return self.raw.get("eventName", "")

    @property
    def source(self) -> str:
        return self.raw.get("eventSource", "")

    @property
    def region(self) -> str:
        return self.raw.get("awsRegion", "")

    @property
    def source_ip(self) -> str:
        return self.raw.get("sourceIPAddress", "")

    @property
    def error_code(self) -> str | None:
        return self.raw.get("errorCode")

    @property
    def event_id(self) -> str:
        return self.raw.get("eventID", "")

    @property
    def time(self) -> datetime | None:
        value = self.raw.get("eventTime")
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @property
    def identity(self) -> dict[str, Any]:
        return self.raw.get("userIdentity") or {}

    @property
    def identity_type(self) -> str:
        return self.identity.get("type", "")

    @property
    def actor(self) -> str:
        """A human-readable name for whoever made the call."""
        ident = self.identity
        if ident.get("type") == "Root":
            return "root"
        issuer = (ident.get("sessionContext") or {}).get("sessionIssuer") or {}
        return (
            ident.get("userName")
            or issuer.get("userName")
            or ident.get("arn")
            or ident.get("principalId")
            or ident.get("invokedBy")
            or "unknown"
        )

    @property
    def request(self) -> dict[str, Any]:
        return self.raw.get("requestParameters") or {}

    @property
    def response(self) -> dict[str, Any]:
        return self.raw.get("responseElements") or {}

    @property
    def additional(self) -> dict[str, Any]:
        return self.raw.get("additionalEventData") or {}


@dataclass
class Finding:
    """Something suspicious that a rule found in one or more events."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    actor: str
    source_ip: str
    region: str
    time: datetime | None
    event_ids: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_event(cls, event: Event, **kwargs: Any) -> "Finding":
        """Build a finding whose context fields come from a single event."""
        kwargs.setdefault("actor", event.actor)
        kwargs.setdefault("source_ip", event.source_ip)
        kwargs.setdefault("region", event.region)
        kwargs.setdefault("time", event.time)
        kwargs.setdefault("event_ids", [event.event_id] if event.event_id else [])
        return cls(**kwargs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "description": self.description,
            "actor": self.actor,
            "source_ip": self.source_ip,
            "region": self.region,
            "time": self.time.isoformat() if self.time else None,
            "event_ids": self.event_ids,
            "mitre": self.mitre,
            "details": self.details,
        }
