from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from cloudtrail_analyzer import Event

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
BASE_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)


def user(name: str = "alice") -> dict[str, Any]:
    return {
        "type": "IAMUser",
        "arn": f"arn:aws:iam::111122223333:user/{name}",
        "accountId": "111122223333",
        "userName": name,
    }


ROOT = {"type": "Root", "arn": "arn:aws:iam::111122223333:root", "accountId": "111122223333"}


def make_event(
    name: str,
    *,
    source: str = "iam.amazonaws.com",
    identity: dict[str, Any] | None = None,
    ip: str = "203.0.113.10",
    region: str = "us-east-1",
    minutes: float = 0,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    error: str | None = None,
    **extra: Any,
) -> Event:
    """Build a minimal but realistic CloudTrail record for tests."""
    record: dict[str, Any] = {
        "eventVersion": "1.10",
        "eventID": f"evt-{next(_ids)}",
        "eventTime": (BASE_TIME + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventName": name,
        "eventSource": source,
        "eventType": "AwsApiCall",
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userIdentity": identity if identity is not None else user(),
        "requestParameters": request,
        "responseElements": response,
    }
    if error:
        record["errorCode"] = error
    record.update(extra)
    return Event(record)


def console_login(*, success: bool, mfa: bool, identity=None, minutes: float = 0, ip="198.51.100.7"):
    return make_event(
        "ConsoleLogin",
        source="signin.amazonaws.com",
        identity=identity,
        ip=ip,
        minutes=minutes,
        response={"ConsoleLogin": "Success" if success else "Failure"},
        additionalEventData={"MFAUsed": "Yes" if mfa else "No"},
    )


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES
