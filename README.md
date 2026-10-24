# CloudGuard

**AWS compliance and risk assessment scanner** (Python, boto3, CIS Benchmarks)

A read-only scanner that audits an AWS account against selected controls of the
**CIS AWS Foundations Benchmark v3.0.0**, rates each finding by severity, and writes
HTML and JSON audit reports with a prioritisation risk score.

## Quick start

```bash
pip install -r requirements.txt

python -m cloudguard --demo                 # scan a MOCKED misconfigured account (no real AWS calls)
python -m pytest -q tests                   # run tests (also fully mocked)

# real account (read-only calls only)
python -m cloudguard --profile myprofile --regions ap-south-1 us-east-1 --out reports/
python -m cloudguard --profile myprofile --include-root --fail-on High   # exit 1 for CI gates
```

Outputs: `cloudguard_report.html` and `cloudguard_report.json`.

## Controls checked

| Check | CIS v3.0.0 | Service | Severity |
| --- | --- | --- | --- |
| S3-001 Bucket publicly accessible (ACL or policy) | 2.1.4 | S3 | High |
| S3-002 Block Public Access not fully enabled | 2.1.4 | S3 | Medium |
| S3-003 Bucket policy does not deny HTTP | 2.1.1 | S3 | Medium |
| IAM-001 Console user without MFA | 1.10 | IAM | Medium |
| IAM-002 Policy allows `*:*` administrative privileges | 1.16 | IAM | High |
| IAM-003 Root account has an access key (`--include-root`) | 1.4 | IAM | High |
| IAM-004 Root account has no MFA (`--include-root`) | 1.5 | IAM | High |
| EC2-001 Security group open to 0.0.0.0/0 on SSH/RDP | 5.2 | EC2 | High |
| EC2-002 Security group open to ::/0 on SSH/RDP | 5.3 | EC2 | High |
| EBS-001 Unencrypted EBS volume | 2.2.1 | EBS | Medium |

Control numbers follow the v3.0.0 numbering; verify against the benchmark version
your auditors use, as numbering changes between releases.

## Demo environment

`--demo` builds a deliberately misconfigured account inside [moto](https://github.com/getmoto/moto):
**13 resources** (3 S3 buckets, 2 IAM users, 2 customer policies, 3 security groups,
3 EBS volumes) producing **7 findings (3 High, 4 Medium)**. The tests assert these
exact numbers.

## Scoring

- Severity weights: Critical 10, High 7, Medium 4, Low 1.
- Risk score (0-100) = weighted findings relative to scan size (a prioritisation aid, not a compliance certificate).
- Compliant resources = share of scanned resources with no findings.

## Minimum IAM permissions (read-only)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "s3:ListAllMyBuckets", "s3:GetBucketAcl", "s3:GetBucketPolicy",
      "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
      "iam:ListUsers", "iam:GetLoginProfile", "iam:ListMFADevices",
      "iam:ListPolicies", "iam:GetPolicyVersion", "iam:GetAccountSummary",
      "ec2:DescribeSecurityGroups", "ec2:DescribeVolumes"
    ],
    "Resource": "*"
  }]
}
```

A service that fails (for example a missing permission) is recorded under "Scan errors"
and does not stop the other checks.

## Project layout

```
cloudguard/
  checks/   s3.py  iam.py  ec2.py  ebs.py     one module per service
  scanner.py   models.py   report.py   demo.py   __main__.py
tests/test_scan.py
```

## Limitations

- Covers a focused subset of the benchmark, not the full control set.
- Only customer-managed IAM policies are inspected for `*:*` (AWS-managed policies are skipped); inline policies and group/role policies are not.
- Treat real findings as leads to verify: it checks configuration, not business context.
