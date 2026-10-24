"""Builds a deliberately misconfigured, fully mocked AWS environment (moto).

Nothing here touches a real AWS account: moto intercepts every boto3 call.
Environment: 13 resources, 7 expected findings (3 High, 4 Medium).
"""

from __future__ import annotations

import json
import os

REGION = "us-east-1"


def _fake_credentials() -> None:
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        os.environ[key] = value
    os.environ.pop("AWS_PROFILE", None)


def populate(session) -> None:
    s3 = session.client("s3", region_name=REGION)
    iam = session.client("iam", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)

    full_block = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    deny_http = lambda bucket: json.dumps(  # noqa: E731
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
    )

    # 1) public-read bucket, no Block Public Access, no HTTP deny -> S3-001 (High) + S3-003 (Medium)
    s3.create_bucket(Bucket="demo-public-assets")
    s3.put_bucket_acl(Bucket="demo-public-assets", ACL="public-read")

    # 2) hardened bucket -> clean
    s3.create_bucket(Bucket="demo-secure-logs")
    s3.put_public_access_block(
        Bucket="demo-secure-logs", PublicAccessBlockConfiguration=full_block
    )
    s3.put_bucket_policy(Bucket="demo-secure-logs", Policy=deny_http("demo-secure-logs"))

    # 3) private but allows plain HTTP -> S3-003 (Medium)
    s3.create_bucket(Bucket="demo-app-backups")
    s3.put_public_access_block(
        Bucket="demo-app-backups", PublicAccessBlockConfiguration=full_block
    )

    # IAM: user with console password and no MFA -> IAM-001 (Medium); service user is clean
    iam.create_user(UserName="alice.analyst")
    iam.create_login_profile(UserName="alice.analyst", Password="Sup3r-Secret-Demo-Pw!")
    iam.create_user(UserName="svc-deploy")

    # IAM: wildcard policy -> IAM-002 (High); scoped policy is clean
    iam.create_policy(
        PolicyName="DemoFullAdmin",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        ),
    )
    iam.create_policy(
        PolicyName="DemoS3ReadOnly",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::demo-secure-logs", "arn:aws:s3:::demo-secure-logs/*"],
                    }
                ],
            }
        ),
    )

    # EC2: SSH open to the world -> EC2-001 (High); HTTPS-only group is clean
    # (the default VPC security group is the third group and is also clean)
    ssh = ec2.create_security_group(GroupName="demo-open-ssh", Description="demo")
    ec2.authorize_security_group_ingress(
        GroupId=ssh["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )
    web = ec2.create_security_group(GroupName="demo-web", Description="demo")
    ec2.authorize_security_group_ingress(
        GroupId=web["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    )

    # EBS: one unencrypted volume -> EBS-001 (Medium); two encrypted are clean
    az = f"{REGION}a"
    ec2.create_volume(AvailabilityZone=az, Size=8, Encrypted=False)
    ec2.create_volume(AvailabilityZone=az, Size=8, Encrypted=True)
    ec2.create_volume(AvailabilityZone=az, Size=16, Encrypted=True)


def run_demo(out_dir: str):
    """Run a full scan inside moto and write reports. Returns the ScanResult."""
    try:
        from moto import mock_aws
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("Demo mode needs moto: pip install 'moto[ec2,s3,iam,sts]'") from exc

    import boto3

    from .report import write_html, write_json
    from .scanner import scan

    _fake_credentials()
    with mock_aws():
        session = boto3.session.Session(region_name=REGION)
        populate(session)
        result = scan(session, [REGION])
    write_json(result, f"{out_dir}/cloudguard_report.json")
    write_html(result, f"{out_dir}/cloudguard_report.html")
    return result
