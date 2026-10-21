# iam-policy-checker

A small, dependency-free Python tool that reviews AWS IAM policy JSON and flags
risky permissions: wildcards, known privilege escalation paths, public
principals, and other patterns that usually mean a policy grants more than
intended.

It works offline on policy documents, so you can run it in CI before a policy
is ever deployed.

## Install

Requires Python 3.9 or newer.

```bash
pip install -e .            # installs the iam-policy-checker command
pip install -e ".[test]"    # also installs pytest
```

You can also run it without installing: `python -m iam_policy_checker ...`.

## Usage

```bash
iam-policy-checker policy.json
iam-policy-checker policies/*.json --format json
aws iam get-policy-version --policy-arn "$ARN" --version-id v3 | iam-policy-checker -
```

Example output:

```
tests/fixtures/escalation.json: 3 finding(s)
  [CRITICAL] IAM009 Privilege escalation: Pass role to new Lambda function (Statement[0])
      Allows iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction. Can create and run a function that executes with a privileged role.
  [HIGH] IAM008 iam:PassRole on all roles (Statement[0])
      Statement[0] (DeployLambdas) lets the caller pass any role, including admin roles, ...
  [MEDIUM] IAM007 Write access on all resources (Statement[0])
      Statement[0] (DeployLambdas) allows lambda:CreateFunction, lambda:InvokeFunction, iam:PassRole on Resource '*'. ...
```

### Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--format text\|json` | `text` | Human-readable report or a JSON array of findings. |
| `--min-severity LEVEL` | `low` | Hide findings below `low`, `medium`, `high` or `critical`. |
| `--fail-on LEVEL` | `high` | Exit with status 1 if any finding is at or above this level. Use `none` to always exit 0. |

Exit codes: `0` no blocking findings, `1` findings at or above `--fail-on`,
`2` a file could not be read or is not a valid policy.

### Accepted input

- A plain policy document (`{"Version": ..., "Statement": [...]}`), identity-based or resource-based.
- AWS CLI output from `aws iam get-policy-version` (`{"PolicyVersion": {"Document": ...}}`).
- An object with a `PolicyDocument` key, whose value may be an object or a JSON string.

## Rules

| ID | Severity | What it flags |
| --- | --- | --- |
| IAM001 | Critical | `Allow` of `Action: "*"` on `Resource: "*"` (full admin). |
| IAM002 | High | `Action: "*"` on a scoped resource. |
| IAM003 | High / Medium | Service-wide wildcards such as `s3:*`. High for sensitive services (`iam`, `sts`, `kms`, `organizations`, `secretsmanager`, `cloudtrail`, `config`, `guardduty`, `account`). |
| IAM004 | Low | Partial wildcards such as `iam:Get*` in a sensitive service. |
| IAM005 | High | `Allow` with `NotAction` (grants everything not listed, including future services). |
| IAM006 | Medium | `Allow` with `NotResource`. |
| IAM007 | Medium | Non-read actions on `Resource: "*"`. Actions starting with Get, List, Describe, Head, View, Search, Lookup, BatchGet, Scan or Query count as reads. |
| IAM008 | High | `iam:PassRole` on all roles. |
| IAM009 | Critical / High / Medium | A known privilege escalation path is fully allowed (see below). |
| IAM010 | Critical / Medium | Resource policy with `Principal: "*"`. Critical with no `Condition`, Medium when a condition limits it. |
| IAM011 | Medium | Secret or data reads (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, `s3:GetObject`) on all resources. |
| IAM012 | Low | Missing `Version`, or a version other than `2012-10-17`. |

### Privilege escalation paths (IAM009)

The checker knows 23 escalation paths, based on the techniques documented by
Rhino Security Labs. A path fires only when **every** action it needs is
allowed somewhere in the policy, so actions can come from different
statements. Wildcards (`iam:Attach*`) and `NotAction` are expanded when
matching. The full list is in [`iam_policy_checker/escalation.py`](iam_policy_checker/escalation.py); highlights:

- `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`
- `iam:Attach{User,Group,Role}Policy`, `iam:Put{User,Group,Role}Policy`
- `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AddUserToGroup`
- `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole`
- `iam:PassRole` combined with EC2, Lambda, Glue, CloudFormation, Data Pipeline, SageMaker or ECS
- `lambda:UpdateFunctionCode`, `glue:UpdateDevEndpoint`

Severity reflects how broadly the actions are granted:

- **Critical**: every action is allowed on all resources with no condition.
- **High**: every action is allowed on all resources, but some only under a condition.
- **Medium**: some actions are limited to specific ARNs. These are leads to
  verify; for example `iam:CreateAccessKey` on `user/${aws:username}` is a
  normal self-service pattern.

An unconditional `Deny` on `Resource: "*"` removes an action from
consideration. Conditional or resource-scoped denies are not evaluated.

When a policy already grants full admin (IAM001), escalation and data-access
findings are suppressed because they add nothing.

## Using it from Python

```python
from iam_policy_checker import load_policy, check_policy

policy = load_policy(open("policy.json").read(), source="policy.json")
for finding in check_policy(policy):
    print(finding.severity.name, finding.rule_id, finding.title)
```

## Limitations

This is a static review of one document at a time. It does not:

- combine multiple policies attached to the same principal, permission
  boundaries, SCPs or session policies;
- evaluate condition keys or resource ARN patterns beyond `"*"`;
- know which actions support resource-level permissions, so IAM007 may flag
  actions that can only ever use `"*"`.

Treat findings as review prompts, and use AWS IAM Access Analyzer policy
validation alongside it for authoritative checks.

## Development

```bash
pip install -e ".[test]"
pytest
```
