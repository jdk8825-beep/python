# CloudTrail analysis report

**Events analyzed:** 63  
**Findings:** 22

| Severity | Count |
| --- | --- |
| CRITICAL | 1 |
| HIGH | 14 |
| MEDIUM | 6 |
| LOW | 1 |

## Findings

| Severity | Rule | Title | Time (UTC) | Actor | Source IP | Region | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CRITICAL | CT-007 | CloudTrail logging disabled or changed | 2026-10-15 02:19:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1562.008 |
| HIGH | CT-005 | Administrator permissions granted | 2026-10-15 02:16:15Z | dev-ci | 203.0.113.45 | us-east-1 | T1098.003, T1484 |
| HIGH | CT-004 | New IAM user or credentials created | 2026-10-15 02:16:30Z | dev-ci | 203.0.113.45 | us-east-1 | T1136.003, T1098.001 |
| HIGH | CT-005 | Administrator permissions granted | 2026-10-15 02:16:45Z | dev-ci | 203.0.113.45 | us-east-1 | T1098.003, T1484 |
| HIGH | CT-008 | Security monitoring disabled | 2026-10-15 02:19:20Z | backup-admin | 203.0.113.45 | us-east-1 | T1562.001 |
| HIGH | CT-008 | Security monitoring disabled | 2026-10-15 02:19:40Z | backup-admin | 203.0.113.45 | us-east-1 | T1562.001 |
| HIGH | CT-008 | Security monitoring disabled | 2026-10-15 02:20:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1562.001 |
| HIGH | CT-010 | Security group opened to the internet | 2026-10-15 02:22:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1562.007 |
| HIGH | CT-011 | S3 bucket made public | 2026-10-15 02:23:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1530 |
| HIGH | CT-011 | S3 bucket made public | 2026-10-15 02:24:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1530 |
| HIGH | CT-012 | Snapshot or AMI shared publicly | 2026-10-15 02:25:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1537 |
| HIGH | CT-009 | KMS key disabled or scheduled for deletion | 2026-10-15 02:35:00Z | backup-admin | 203.0.113.45 | us-east-1 | T1485, T1486 |
| HIGH | CT-003 | Repeated failed console logins | 2026-10-15 04:00:00Z | alice | 198.51.100.23 | us-east-1 | T1110 |
| HIGH | CT-001 | Root account used | 2026-10-15 06:00:00Z | root | 192.0.2.99 | us-east-1 | T1078.004 |
| HIGH | CT-001 | Root account used | 2026-10-15 06:01:00Z | root | 192.0.2.99 | us-east-1 | T1078.004 |
| MEDIUM | CT-006 | Burst of access-denied errors | 2026-10-15 02:10:00Z | dev-ci | 203.0.113.45 | us-east-1 | T1580, T1087.004 |
| MEDIUM | CT-004 | New IAM user or credentials created | 2026-10-15 02:16:00Z | dev-ci | 203.0.113.45 | us-east-1 | T1136.003, T1098.001 |
| MEDIUM | CT-013 | Activity in an unapproved region: ap-southeast-1 | 2026-10-15 02:30:00Z | backup-admin | 203.0.113.45 | ap-southeast-1 | T1535 |
| MEDIUM | CT-009 | KMS key disabled or scheduled for deletion (attempt failed: AccessDeniedException) | 2026-10-15 02:36:00Z | backup-admin | 203.0.113.45 | eu-west-1 | T1485, T1486 |
| MEDIUM | CT-013 | Activity in an unapproved region: eu-west-1 | 2026-10-15 02:36:00Z | backup-admin | 203.0.113.45 | eu-west-1 | T1535 |
| MEDIUM | CT-002 | Console login without MFA | 2026-10-15 04:06:00Z | alice | 198.51.100.23 | us-east-1 | T1078.004 |
| LOW | CT-010 | Security group opened to the internet | 2026-10-14 09:12:00Z | alice | 192.0.2.10 | us-east-1 | T1562.007 |
