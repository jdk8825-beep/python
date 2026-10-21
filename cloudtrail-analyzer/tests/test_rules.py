from __future__ import annotations

import json

import pytest

from cloudtrail_analyzer import Config, Severity
from cloudtrail_analyzer import rules as r

from .conftest import ROOT, console_login, make_event, user


def run(rule_cls, events, config=None):
    return rule_cls().evaluate(events, config or Config())


# --- CT-001 root usage --------------------------------------------------------


def test_root_api_call_is_flagged():
    findings = run(r.RootAccountUsage, [make_event("ListUsers", identity=ROOT)])
    assert len(findings) == 1
    assert findings[0].actor == "root"
    assert findings[0].severity is Severity.HIGH


def test_root_calls_made_by_aws_services_are_ignored():
    service_call = make_event("Decrypt", identity={**ROOT, "invokedBy": "s3.amazonaws.com"})
    service_event = make_event("CreateSnapshot", identity=ROOT, eventType="AwsServiceEvent")
    assert run(r.RootAccountUsage, [service_call, service_event]) == []


def test_non_root_is_ignored():
    assert run(r.RootAccountUsage, [make_event("ListUsers")]) == []


# --- CT-002 console login without MFA -----------------------------------------


def test_successful_login_without_mfa_is_flagged():
    findings = run(r.ConsoleLoginWithoutMFA, [console_login(success=True, mfa=False)])
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_root_login_without_mfa_is_critical():
    findings = run(r.ConsoleLoginWithoutMFA, [console_login(success=True, mfa=False, identity=ROOT)])
    assert findings[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "event",
    [
        console_login(success=True, mfa=True),
        console_login(success=False, mfa=False),
        console_login(success=True, mfa=False, identity={"type": "AssumedRole", "arn": "x"}),
    ],
    ids=["with-mfa", "failed-login", "federated-sso"],
)
def test_login_without_mfa_ignores_safe_cases(event):
    assert run(r.ConsoleLoginWithoutMFA, [event]) == []


# --- CT-003 brute force -------------------------------------------------------


def test_failed_logins_at_threshold_are_flagged():
    events = [console_login(success=False, mfa=False, minutes=i) for i in range(5)]
    findings = run(r.BruteForceConsoleLogin, events)
    assert len(findings) == 1
    assert findings[0].details["count_in_window"] == 5
    assert findings[0].source_ip == "198.51.100.7"
    assert len(findings[0].event_ids) == 5


def test_failed_logins_below_threshold_are_ignored():
    events = [console_login(success=False, mfa=False, minutes=i) for i in range(4)]
    assert run(r.BruteForceConsoleLogin, events) == []


def test_failed_logins_spread_beyond_window_are_ignored():
    # Five failures, but 10 minutes apart: never more than 2 inside 15 minutes.
    events = [console_login(success=False, mfa=False, minutes=i * 10) for i in range(5)]
    assert run(r.BruteForceConsoleLogin, events) == []


def test_failed_logins_are_counted_per_source_ip():
    events = [console_login(success=False, mfa=False, ip=f"198.51.100.{i}") for i in range(10)]
    assert run(r.BruteForceConsoleLogin, events) == []


def test_threshold_and_window_are_configurable():
    events = [console_login(success=False, mfa=False, minutes=i * 10) for i in range(3)]
    config = Config(failed_login_threshold=3, window_minutes=30)
    assert len(run(r.BruteForceConsoleLogin, events, config)) == 1


# --- CT-004 IAM persistence ---------------------------------------------------


def test_create_user_is_medium():
    findings = run(r.IAMPersistence, [make_event("CreateUser", request={"userName": "eve"})])
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].details["targetUser"] == "eve"


def test_access_key_for_another_user_is_high():
    event = make_event("CreateAccessKey", request={"userName": "backup-admin"})
    assert run(r.IAMPersistence, [event])[0].severity is Severity.HIGH


def test_access_key_for_yourself_stays_medium():
    event = make_event("CreateAccessKey", identity=user("alice"), request={"userName": "alice"})
    assert run(r.IAMPersistence, [event])[0].severity is Severity.MEDIUM


# --- CT-005 admin policy ------------------------------------------------------


def test_attach_administrator_access_is_flagged():
    event = make_event(
        "AttachUserPolicy",
        request={"userName": "eve", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    )
    findings = run(r.AdminPolicyGranted, [event])
    assert findings[0].details["target"] == "eve"


def test_attach_scoped_policy_is_ignored():
    event = make_event(
        "AttachRolePolicy",
        request={"roleName": "app", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    )
    assert run(r.AdminPolicyGranted, [event]) == []


@pytest.mark.parametrize("encode", [json.dumps, lambda d: json.dumps(d).replace('"', "%22")])
def test_inline_star_star_policy_is_flagged(encode):
    doc = {"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}]}
    event = make_event(
        "PutRolePolicy", request={"roleName": "app", "policyName": "p", "policyDocument": encode(doc)}
    )
    assert len(run(r.AdminPolicyGranted, [event])) == 1


def test_inline_scoped_policy_is_ignored():
    doc = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    event = make_event("PutUserPolicy", request={"userName": "a", "policyDocument": json.dumps(doc)})
    assert run(r.AdminPolicyGranted, [event]) == []


def test_inline_deny_star_is_ignored():
    doc = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    event = make_event("PutUserPolicy", request={"userName": "a", "policyDocument": json.dumps(doc)})
    assert run(r.AdminPolicyGranted, [event]) == []


# --- CT-006 access-denied burst -----------------------------------------------


def test_access_denied_burst_is_flagged():
    events = [make_event("ListRoles", error="AccessDenied", minutes=i * 0.5) for i in range(10)]
    findings = run(r.AccessDeniedBurst, events)
    assert len(findings) == 1
    assert findings[0].actor == "alice"


def test_mixed_error_codes_count_together():
    events = [make_event("DescribeInstances", error="Client.UnauthorizedOperation", minutes=i)
              for i in range(5)]
    events += [make_event("ListRoles", error="AccessDenied", minutes=i) for i in range(5)]
    assert len(run(r.AccessDeniedBurst, events)) == 1


def test_other_errors_do_not_count():
    events = [make_event("GetObject", error="NoSuchKey", minutes=i * 0.1) for i in range(20)]
    assert run(r.AccessDeniedBurst, events) == []


# --- CT-007 / CT-008 / CT-009 defense evasion and destruction -----------------


def test_stop_logging_is_critical():
    event = make_event("StopLogging", source="cloudtrail.amazonaws.com", request={"name": "org-trail"})
    findings = run(r.CloudTrailTampering, [event])
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].details["trail"] == "org-trail"


def test_update_trail_is_high():
    event = make_event("UpdateTrail", source="cloudtrail.amazonaws.com", request={"name": "t"})
    assert run(r.CloudTrailTampering, [event])[0].severity is Severity.HIGH


def test_failed_attempt_is_reported_one_level_lower():
    event = make_event("StopLogging", source="cloudtrail.amazonaws.com", error="AccessDenied")
    finding = run(r.CloudTrailTampering, [event])[0]
    assert finding.severity is Severity.HIGH
    assert "attempt failed: AccessDenied" in finding.title


def test_failed_attempt_never_drops_below_low():
    event = make_event("AuthorizeSecurityGroupIngress", source="ec2.amazonaws.com", error="X",
                       request={"cidrIp": "0.0.0.0/0", "ipProtocol": "tcp",
                                "fromPort": 443, "toPort": 443})
    assert run(r.SecurityGroupOpenToWorld, [event])[0].severity is Severity.LOW


def test_read_only_cloudtrail_calls_are_ignored():
    event = make_event("DescribeTrails", source="cloudtrail.amazonaws.com")
    assert run(r.CloudTrailTampering, [event]) == []


@pytest.mark.parametrize(
    "name", ["DeleteDetector", "StopConfigurationRecorder", "DeleteFlowLogs", "DisableSecurityHub"]
)
def test_security_monitoring_disabled(name):
    assert len(run(r.SecurityMonitoringDisabled, [make_event(name)])) == 1


def test_kms_key_deletion():
    event = make_event("ScheduleKeyDeletion", source="kms.amazonaws.com",
                       request={"keyId": "k1", "pendingWindowInDays": 7})
    findings = run(r.KMSKeyDeletion, [event])
    assert findings[0].details == {"eventName": "ScheduleKeyDeletion", "keyId": "k1",
                                   "pendingWindowInDays": 7}


# --- CT-010 security groups ---------------------------------------------------


def sg_event(cidr_key, cidr, from_port, to_port, protocol="tcp"):
    range_key = "ipv6Ranges" if cidr_key == "cidrIpv6" else "ipRanges"
    return make_event(
        "AuthorizeSecurityGroupIngress",
        source="ec2.amazonaws.com",
        request={
            "groupId": "sg-1",
            "ipPermissions": {"items": [{
                "ipProtocol": protocol, "fromPort": from_port, "toPort": to_port,
                range_key: {"items": [{cidr_key: cidr}]},
            }]},
        },
    )


@pytest.mark.parametrize(
    "event, severity, ports",
    [
        (sg_event("cidrIp", "0.0.0.0/0", 22, 22), Severity.HIGH, ["22/SSH"]),
        (sg_event("cidrIpv6", "::/0", 3389, 3389), Severity.HIGH, ["3389/RDP"]),
        (sg_event("cidrIp", "0.0.0.0/0", 0, 65535), Severity.HIGH, None),
        (sg_event("cidrIp", "0.0.0.0/0", -1, -1, protocol="-1"), Severity.HIGH, None),
        (sg_event("cidrIp", "0.0.0.0/0", 8080, 8080), Severity.MEDIUM, []),
        (sg_event("cidrIp", "0.0.0.0/0", 443, 443), Severity.LOW, []),
    ],
    ids=["ssh", "rdp-ipv6", "all-ports", "all-protocols", "custom-port", "https"],
)
def test_security_group_open_to_world(event, severity, ports):
    finding = run(r.SecurityGroupOpenToWorld, [event])[0]
    assert finding.severity is severity
    if ports is not None:
        assert finding.details["sensitivePorts"] == ports


def test_security_group_private_cidr_is_ignored():
    assert run(r.SecurityGroupOpenToWorld, [sg_event("cidrIp", "10.0.0.0/8", 22, 22)]) == []


def test_only_open_rules_decide_severity():
    # SSH to a private range plus HTTPS to the world should be LOW, not HIGH.
    event = make_event(
        "AuthorizeSecurityGroupIngress",
        source="ec2.amazonaws.com",
        request={"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
             "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}},
            {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
             "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}},
        ]}},
    )
    assert run(r.SecurityGroupOpenToWorld, [event])[0].severity is Severity.LOW


def test_modify_security_group_rules_format():
    event = make_event(
        "ModifySecurityGroupRules",
        source="ec2.amazonaws.com",
        request={"ModifySecurityGroupRulesRequest": {"GroupId": "sg-1", "SecurityGroupRule": {
            "SecurityGroupRule": {"IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
                                  "CidrIpv4": "0.0.0.0/0"}}}},
    )
    finding = run(r.SecurityGroupOpenToWorld, [event])[0]
    assert finding.details["sensitivePorts"] == ["3306/MySQL"]


# --- CT-011 S3 ----------------------------------------------------------------


def test_bucket_acl_all_users_is_flagged():
    event = make_event("PutBucketAcl", source="s3.amazonaws.com", request={
        "bucketName": "b",
        "AccessControlPolicy": {"AccessControlList": {"Grant": [{"Grantee": {
            "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]}},
    })
    assert run(r.S3BucketMadePublic, [event])[0].details["bucket"] == "b"


def test_private_bucket_acl_is_ignored():
    event = make_event("PutBucketAcl", source="s3.amazonaws.com", request={
        "bucketName": "b", "AccessControlPolicy": {"Owner": {"ID": "abc"}}})
    assert run(r.S3BucketMadePublic, [event]) == []


@pytest.mark.parametrize("principal, flagged", [
    ("*", True),
    ({"AWS": "*"}, True),
    ({"AWS": ["arn:aws:iam::1:root", "*"]}, True),
    ({"Service": "cloudfront.amazonaws.com"}, False),
    ({"AWS": "arn:aws:iam::444455556666:root"}, False),
])
def test_bucket_policy_principal(principal, flagged):
    policy = {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject",
                             "Resource": "arn:aws:s3:::b/*"}]}
    event = make_event("PutBucketPolicy", source="s3.amazonaws.com",
                       request={"bucketName": "b", "bucketPolicy": policy})
    assert bool(run(r.S3BucketMadePublic, [event])) is flagged


def test_bucket_policy_with_condition_is_not_public():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                             "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpce": "v"}}}]}
    event = make_event("PutBucketPolicy", source="s3.amazonaws.com",
                       request={"bucketName": "b", "bucketPolicy": json.dumps(policy)})
    assert run(r.S3BucketMadePublic, [event]) == []


def test_public_access_block_removed():
    event = make_event("DeleteBucketPublicAccessBlock", source="s3.amazonaws.com",
                       request={"bucketName": "b"})
    assert len(run(r.S3BucketMadePublic, [event])) == 1


@pytest.mark.parametrize("value, flagged", [(False, True), (True, False)])
def test_public_access_block_settings(value, flagged):
    event = make_event("PutBucketPublicAccessBlock", source="s3.amazonaws.com", request={
        "bucketName": "b",
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": value, "BlockPublicPolicy": True}})
    assert bool(run(r.S3BucketMadePublic, [event])) is flagged


# --- CT-012 public snapshots --------------------------------------------------


def test_ebs_snapshot_shared_with_all():
    event = make_event("ModifySnapshotAttribute", source="ec2.amazonaws.com", request={
        "snapshotId": "snap-1", "createVolumePermission": {"add": {"items": [{"group": "all"}]}}})
    assert run(r.PublicSnapshot, [event])[0].details["resource"] == "snap-1"


def test_snapshot_shared_with_one_account_is_ignored():
    event = make_event("ModifySnapshotAttribute", source="ec2.amazonaws.com", request={
        "snapshotId": "snap-1",
        "createVolumePermission": {"add": {"items": [{"userId": "444455556666"}]}}})
    assert run(r.PublicSnapshot, [event]) == []


def test_rds_snapshot_shared_with_all():
    event = make_event("ModifyDBSnapshotAttribute", source="rds.amazonaws.com", request={
        "dBSnapshotIdentifier": "db-snap", "attributeName": "restore", "valuesToAdd": ["all"]})
    assert run(r.PublicSnapshot, [event])[0].details["resource"] == "db-snap"


# --- CT-013 regions -----------------------------------------------------------


def test_region_rule_is_off_without_allowed_regions():
    assert run(r.UnapprovedRegion, [make_event("RunInstances", region="ap-south-1")]) == []


def test_region_rule_groups_by_actor_and_region():
    events = [make_event("RunInstances", region="ap-south-1", minutes=i) for i in range(3)]
    events.append(make_event("ListUsers", region="us-east-1"))
    config = Config(allowed_regions=frozenset({"us-east-1"}))
    findings = run(r.UnapprovedRegion, events, config)
    assert len(findings) == 1
    assert findings[0].details["count"] == 3
    assert len(findings[0].event_ids) == 3
