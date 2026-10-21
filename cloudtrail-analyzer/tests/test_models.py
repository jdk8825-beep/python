from cloudtrail_analyzer import Event, Severity

import pytest


def test_event_accessors_tolerate_missing_fields():
    event = Event({})
    assert event.name == ""
    assert event.time is None
    assert event.actor == "unknown"
    assert event.request == {}
    assert event.error_code is None


def test_event_time_parses_cloudtrail_format():
    event = Event({"eventTime": "2026-10-15T02:19:00Z"})
    assert event.time.isoformat() == "2026-10-15T02:19:00+00:00"


def test_invalid_time_is_none():
    assert Event({"eventTime": "yesterday"}).time is None


@pytest.mark.parametrize("identity, expected", [
    ({"type": "Root", "arn": "arn:aws:iam::1:root"}, "root"),
    ({"type": "IAMUser", "userName": "alice"}, "alice"),
    ({"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/deploy/s",
      "sessionContext": {"sessionIssuer": {"userName": "deploy"}}}, "deploy"),
    ({"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}, "ec2.amazonaws.com"),
])
def test_actor(identity, expected):
    assert Event({"userIdentity": identity}).actor == expected


def test_severity_parse():
    assert Severity.parse(" High ") is Severity.HIGH
    with pytest.raises(ValueError, match="expected one of"):
        Severity.parse("urgent")
