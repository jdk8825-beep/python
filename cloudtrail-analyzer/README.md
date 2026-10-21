# CloudTrail Analyzer

A small, dependency-free Python tool that reads AWS CloudTrail logs and flags
activity that usually means an account is under attack: disabled logging, new
admin users, public S3 buckets, brute-forced console logins and more. Every
finding is tagged with a severity and the matching
[MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/cloud/iaas/) technique.

```
$ cloudtrail-analyzer samples/compromised_credentials.json
Analyzed 43 events, 19 findings (1 critical, 14 high, 4 medium, 0 low)

[CRITICAL] CT-007 CloudTrail logging disabled or changed
    when:   2026-10-15 02:19:00Z   region: us-east-1
    who:    backup-admin   from: 203.0.113.45
    detail: eventName=StopLogging; trail=arn:aws:cloudtrail:us-east-1:111122223333:trail/org-trail
    mitre:  T1562.008

[HIGH] CT-005 Administrator permissions granted
    when:   2026-10-15 02:16:15Z   region: us-east-1
    who:    dev-ci   from: 203.0.113.45
    detail: eventName=AttachUserPolicy; target=backup-admin; policyArn=arn:aws:iam::aws:policy/AdministratorAccess
    mitre:  T1098.003, T1484
...
```

A full Markdown report for both sample files is in
[`samples/sample_report.md`](samples/sample_report.md).

## Why this exists

CloudTrail records every API call in an AWS account, but the raw logs are
thousands of nested JSON records. The first questions during an incident are
usually the same: *did anyone turn off logging, create a backdoor user, or
open something to the internet?* This tool answers those questions in one
command, and it doubles as a readable reference for what each attack looks
like in CloudTrail.

## Quick start

Requires Python 3.9 or newer. There are no runtime dependencies.

```bash
cd cloudtrail-analyzer
pip install -e ".[test]"      # installs the `cloudtrail-analyzer` command and pytest

cloudtrail-analyzer samples/                       # scan a file or a whole directory
cloudtrail-analyzer samples/ --min-severity high   # hide low/medium findings
cloudtrail-analyzer samples/ -f json -o report.json
cloudtrail-analyzer samples/ -f markdown -o report.md
cloudtrail-analyzer --list-rules
```

You can also run it without installing: `python -m cloudtrail_analyzer samples/`.

### Scanning your own logs

CloudTrail delivers gzipped JSON files to S3. Download them and point the tool
at the folder; it searches subfolders and reads `.json`, `.json.gz` and
`.jsonl` files.

```bash
aws s3 sync s3://my-cloudtrail-bucket/AWSLogs/111122223333/CloudTrail/us-east-1/2026/10/15/ ./logs/
cloudtrail-analyzer ./logs/ --allowed-regions us-east-1,us-west-2
```

### Options

| Option | What it does |
| --- | --- |
| `-f, --format {text,json,markdown}` | Output format. Text is colored when printed to a terminal. |
| `-o, --output FILE` | Write the report to a file instead of stdout. |
| `--min-severity LEVEL` | Only show findings at or above `low`, `medium`, `high` or `critical`. |
| `--fail-on LEVEL` | Exit with status 1 if any finding is at or above this level. Useful in CI or a scheduled job. |
| `--allowed-regions LIST` | Comma-separated regions you actually use. Turns on rule CT-013. |
| `--failed-login-threshold N` | Failed logins from one IP that count as brute force (default 5). |
| `--access-denied-threshold N` | Access-denied errors from one principal that count as a burst (default 10). |
| `--window-minutes N` | Time window for the two threshold rules (default 15). |

Exit codes: `0` success, `1` a finding matched `--fail-on`, `2` a log file
could not be read.

## Detection rules

| ID | Severity | What it catches | MITRE ATT&CK |
| --- | --- | --- | --- |
| CT-001 | High | Root user making API calls or signing in | T1078.004 Valid Accounts: Cloud |
| CT-002 | Medium (Critical for root) | Successful console login without MFA | T1078.004 |
| CT-003 | High | Many failed console logins from one IP in a short window | T1110 Brute Force |
| CT-004 | Medium (High for keys made for someone else) | `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` | T1136.003, T1098.001 |
| CT-005 | High | `AdministratorAccess`/`IAMFullAccess` attached, or an inline policy allowing `*` on `*` | T1098.003, T1484 |
| CT-006 | Medium | Burst of `AccessDenied`/`UnauthorizedOperation` errors from one principal (permission enumeration) | T1580, T1087.004 |
| CT-007 | Critical (High for config changes) | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` | T1562.008 Disable Cloud Logs |
| CT-008 | High | GuardDuty, AWS Config, VPC Flow Logs, Security Hub or Access Analyzer turned off | T1562.001 |
| CT-009 | High | KMS key disabled or scheduled for deletion | T1485, T1486 |
| CT-010 | Medium (High for SSH/RDP/DB ports, Low for 80/443 only) | Security group rule open to `0.0.0.0/0` or `::/0` | T1562.007 |
| CT-011 | High | Bucket ACL granting `AllUsers`, bucket policy with `Principal: "*"`, or Block Public Access removed | T1530 |
| CT-012 | High | EBS snapshot, AMI or RDS snapshot shared with all accounts | T1537 |
| CT-013 | Medium | Activity in a region outside `--allowed-regions` (off unless you set it) | T1535 |

**Failed attempts count too.** If AWS rejected a call (the record has an
`errorCode`), the finding is still reported, one severity level lower and with
"attempt failed" in the title. A blocked attempt to stop CloudTrail is still
something you want to know about.

**Noise reduction.** Calls AWS services make on your behalf (`invokedBy`,
`AwsServiceEvent`) don't count as root usage or region violations. SSO and
other federated logins are not flagged for missing MFA, because MFA is
enforced at the identity provider.

## The sample logs

Both files in [`samples/`](samples/) are synthetic. They use the documentation
IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and the example
account ID `111122223333`, so nothing in them is real.

**`benign_activity.json`** is a normal working day: engineers signing in with
MFA, a CI role deploying Lambda code, a database port opened to a private
subnet, a public HTTPS load balancer, and a few harmless permission errors.
It produces no findings above Low.

**`compromised_credentials.json`** tells one attack story from start to finish:

1. An attacker uses a leaked access key for the `dev-ci` user from
   `203.0.113.45` and probes what it can do (CT-006).
2. The key turns out to have IAM permissions. The attacker creates a
   `backup-admin` user, gives it `AdministratorAccess`, and makes an access
   key for it (CT-004, CT-005).
3. As `backup-admin`, they stop CloudTrail and switch off GuardDuty, AWS
   Config and VPC Flow Logs (CT-007, CT-008).
4. They open SSH and PostgreSQL to the internet, make a customer-data bucket
   public and share an EBS snapshot with every AWS account (CT-010, CT-011,
   CT-012).
5. They launch GPU instances in `ap-southeast-1`, a region the company does
   not use, and schedule KMS keys for deletion (CT-013, CT-009).
6. Separately, someone brute-forces `alice`'s console password and signs in
   without MFA (CT-003, CT-002), and the root user signs in (CT-001).

Every rule fires at least once on this file, which the end-to-end tests check.

## Project layout

```
cloudtrail-analyzer/
├── cloudtrail_analyzer/
│   ├── models.py     # Event wrapper, Finding, Severity
│   ├── loader.py     # reads .json / .json.gz / .jsonl files and folders
│   ├── rules.py      # all detection rules
│   ├── analyzer.py   # runs rules, filters and sorts findings
│   ├── report.py     # text, JSON and Markdown output
│   └── cli.py        # command-line interface
├── samples/          # synthetic logs and a generated report
└── tests/            # pytest suite (85 tests)
```

## Running the tests

```bash
cd cloudtrail-analyzer
pip install -e ".[test]"
pytest
```

GitHub Actions runs the suite on Python 3.9, 3.11 and 3.13 and smoke-tests the
CLI against both sample files.

## Adding a rule

Most rules look at one event at a time. Subclass `EventRule`, list the event
names you care about, and return a dict of details when something is
suspicious (or `None` when it isn't):

```python
class LoginProfileDeleted(EventRule):
    rule_id = "CT-014"
    title = "Console password removed"
    severity = Severity.MEDIUM
    mitre = ("T1531",)
    event_names = frozenset({"DeleteLoginProfile"})
    description = "Removing a user's console password can lock out the real owner."

    def check(self, event, config):
        return {"targetUser": event.request.get("userName")}
```

For "too many X in Y minutes" rules, subclass `ThresholdRule` and implement
`matches`, `key` and `threshold`. Then add the class to `ALL_RULES` at the
bottom of `rules.py` and write a test for it.

## Limitations and next steps

- It analyzes files you already have. It doesn't pull from S3 or CloudTrail
  Lake directly; a `--from-s3` option using `boto3` would be a natural addition.
- Rules are stateless pattern matches plus two simple thresholds. It doesn't
  learn a baseline of "normal" for your account, so something like "first time
  this user called this API" isn't detected yet.
- Findings aren't correlated into incidents. In the sample, the brute force and
  the no-MFA login from the same IP are reported separately even though they
  are clearly one event chain.
- Only management events are covered. S3 data events (`GetObject` at volume)
  would add exfiltration detection.
