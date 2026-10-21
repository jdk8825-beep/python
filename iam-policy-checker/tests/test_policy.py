import json

import pytest

from iam_policy_checker import PolicyError, load_policy, parse_policy

DOC = {
    "Version": "2012-10-17",
    "Statement": {"Sid": "One", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
}


def test_single_statement_and_strings_are_normalised_to_lists():
    policy = parse_policy(DOC)
    (stmt,) = policy.statements
    assert stmt.actions == ["s3:GetObject"]
    assert stmt.resources == ["*"]
    assert stmt.label == "Statement[0] (One)"


def test_unwraps_aws_cli_get_policy_version_output():
    wrapped = {"PolicyVersion": {"Document": DOC, "VersionId": "v1"}}
    assert parse_policy(wrapped).version == "2012-10-17"


def test_unwraps_policy_document_given_as_json_string():
    wrapped = {"PolicyDocument": json.dumps(DOC)}
    assert len(parse_policy(wrapped).statements) == 1


def test_principal_map_is_flattened():
    doc = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ["arn:aws:iam::1:root", "*"], "Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ]
    }
    (stmt,) = parse_policy(doc).statements
    assert stmt.has_principal
    assert set(stmt.principals) == {"arn:aws:iam::1:root", "*", "ec2.amazonaws.com"}


@pytest.mark.parametrize(
    "text, message",
    [
        ("not json", "Invalid JSON"),
        ("[]", "must be a JSON object"),
        ("{}", "no 'Statement'"),
        ('{"Statement": [{"Effect": "Maybe", "Action": "*"}]}', "invalid Effect"),
        ('{"Statement": [{"Effect": "Allow", "Resource": "*"}]}', "neither Action nor NotAction"),
    ],
)
def test_invalid_documents_raise(text, message):
    with pytest.raises(PolicyError, match=message):
        load_policy(text)
