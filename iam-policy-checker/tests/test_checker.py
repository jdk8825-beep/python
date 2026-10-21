import pytest

from iam_policy_checker import Severity, check_policy, parse_policy


def run(*statements, version="2012-10-17"):
    doc = {"Statement": list(statements)}
    if version is not None:
        doc["Version"] = version
    return check_policy(parse_policy(doc))


def rules(findings):
    return {f.rule_id for f in findings}


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def test_least_privilege_policy_is_clean():
    findings = run(allow(["s3:GetObject"], "arn:aws:s3:::bucket/*"))
    assert findings == []


def test_full_admin_is_critical_and_suppresses_escalation_noise():
    findings = run(allow("*"))
    assert rules(findings) == {"IAM001"}
    assert findings[0].severity is Severity.CRITICAL


def test_wildcard_action_on_scoped_resource():
    findings = run(allow("*", "arn:aws:s3:::bucket/*"))
    (f,) = by_rule(findings, "IAM002")
    assert f.severity is Severity.HIGH


@pytest.mark.parametrize(
    "action, severity",
    [("s3:*", Severity.MEDIUM), ("iam:*", Severity.HIGH), ("KMS:*", Severity.HIGH)],
)
def test_service_wildcard(action, severity):
    findings = run(allow(action, "arn:aws:s3:::bucket"))
    (f,) = by_rule(findings, "IAM003")
    assert f.severity is severity


def test_partial_wildcard_in_sensitive_service():
    findings = run(allow("iam:Get*", "arn:aws:iam::123456789012:role/app"))
    assert rules(findings) == {"IAM004"}
    assert by_rule(findings, "IAM004")[0].severity is Severity.LOW


def test_partial_wildcard_in_ordinary_service_is_not_flagged():
    assert run(allow("s3:Get*", "arn:aws:s3:::bucket/*")) == []


def test_allow_not_action():
    findings = run({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert "IAM005" in rules(findings)


def test_allow_not_resource():
    findings = run(
        {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"}
    )
    assert "IAM006" in rules(findings)


def test_write_on_all_resources():
    findings = run(allow(["ec2:TerminateInstances", "ec2:DescribeInstances"]))
    (f,) = by_rule(findings, "IAM007")
    assert "ec2:TerminateInstances" in f.detail
    assert "DescribeInstances" not in f.detail


def test_read_only_on_all_resources_is_fine():
    assert run(allow(["ec2:DescribeInstances", "cloudwatch:GetMetricData"])) == []


def test_passrole_on_all_roles():
    findings = run(allow("iam:PassRole"))
    assert "IAM008" in rules(findings)


def test_passrole_scoped_to_one_role_is_not_flagged():
    findings = run(allow("iam:PassRole", "arn:aws:iam::123456789012:role/app"))
    assert "IAM008" not in rules(findings)


@pytest.mark.parametrize(
    "actions, path_name",
    [
        (["iam:CreatePolicyVersion"], "Create new policy version"),
        (["iam:AttachUserPolicy"], "Attach managed policy to user"),
        (["iam:PassRole", "ec2:RunInstances"], "Pass role to new EC2 instance"),
        (["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], "Update role trust policy"),
        (["lambda:UpdateFunctionCode"], "Update existing Lambda code"),
    ],
)
def test_escalation_paths_detected(actions, path_name):
    findings = run(allow(actions))
    titles = [f.title for f in by_rule(findings, "IAM009")]
    assert f"Privilege escalation: {path_name}" in titles


def test_escalation_needs_every_action():
    findings = run(allow("ec2:RunInstances"))
    assert "IAM009" not in rules(findings)


def test_escalation_combines_actions_across_statements():
    findings = run(
        allow("iam:PassRole", "arn:aws:iam::123456789012:role/*"),
        allow("ec2:RunInstances"),
    )
    (f,) = by_rule(findings, "IAM009")
    assert f.statements == [0, 1]
    # PassRole is scoped by ARN, so this is a lead to verify rather than a certainty.
    assert f.severity is Severity.MEDIUM


def test_escalation_via_wildcard_pattern():
    findings = run(allow("iam:Attach*"))
    titles = {f.title for f in by_rule(findings, "IAM009")}
    assert {
        "Privilege escalation: Attach managed policy to user",
        "Privilege escalation: Attach managed policy to group",
        "Privilege escalation: Attach managed policy to role",
    } <= titles


def test_escalation_via_not_action():
    findings = run({"Effect": "Allow", "NotAction": "s3:*", "Resource": "*"})
    assert by_rule(findings, "IAM009")


def test_escalation_severity_unscoped_is_critical():
    (f,) = by_rule(run(allow("iam:CreateAccessKey")), "IAM009")
    assert f.severity is Severity.CRITICAL


def test_escalation_with_condition_is_high():
    stmt = allow("iam:CreateAccessKey", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    (f,) = by_rule(run(stmt), "IAM009")
    assert f.severity is Severity.HIGH


def test_explicit_deny_blocks_escalation():
    findings = run(
        allow("iam:*"),
        {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},
    )
    assert "IAM009" not in rules(findings)


def test_conditional_deny_does_not_block_escalation():
    findings = run(
        allow("iam:CreateAccessKey"),
        {
            "Effect": "Deny",
            "Action": "iam:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}},
        },
    )
    assert "IAM009" in rules(findings)


def test_action_matching_is_case_insensitive():
    findings = run(allow("IAM:createpolicyversion"))
    assert by_rule(findings, "IAM009")


def test_public_principal_without_condition():
    stmt = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*",
    }
    (f,) = by_rule(run(stmt), "IAM010")
    assert f.severity is Severity.CRITICAL


def test_public_principal_with_condition():
    stmt = {
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*",
        "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
    }
    (f,) = by_rule(run(stmt), "IAM010")
    assert f.severity is Severity.MEDIUM


def test_specific_principal_is_fine():
    stmt = {
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*",
    }
    assert run(stmt) == []


def test_sensitive_data_on_all_resources():
    findings = run(allow("secretsmanager:GetSecretValue"))
    assert "IAM011" in rules(findings)


def test_sensitive_data_not_double_reported_with_service_wildcard():
    findings = run(allow("secretsmanager:*"))
    assert "IAM011" not in rules(findings)
    assert "IAM003" in rules(findings)


@pytest.mark.parametrize("version", [None, "2008-10-17"])
def test_missing_or_old_version(version):
    findings = run(allow("s3:GetObject", "arn:aws:s3:::bucket/*"), version=version)
    assert rules(findings) == {"IAM012"}


def test_findings_sorted_most_severe_first():
    findings = run(allow(["iam:PassRole", "ec2:RunInstances"]), version=None)
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_deny_statements_are_not_flagged_for_wildcards():
    findings = run(
        allow("s3:GetObject", "arn:aws:s3:::bucket/*"),
        {"Effect": "Deny", "Action": "*", "Resource": "*"},
    )
    assert findings == []
