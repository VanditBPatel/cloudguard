"""Orchestrates the checks and builds a ScanResult."""

from __future__ import annotations

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .checks import ebs, ec2, iam, s3
from .models import ScanResult


def scan(session: boto3.session.Session, regions: list[str], include_root: bool = False) -> ScanResult:
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Could not authenticate to AWS: {exc}") from exc

    result = ScanResult(account_id=account_id, regions=regions)

    runners = [
        ("S3", lambda: s3.run(session, regions)),
        ("IAM", lambda: iam.run(session, regions, include_root=include_root)),
        ("EC2", lambda: ec2.run(session, regions)),
        ("EBS", lambda: ebs.run(session, regions)),
    ]
    for service, runner in runners:
        try:
            count, findings = runner()
        except (BotoCoreError, ClientError) as exc:
            # one failing service (e.g. missing permission) must not hide the rest
            result.errors.append(f"{service}: {exc}")
            result.resources_scanned[service] = 0
            continue
        result.resources_scanned[service] = count
        result.findings.extend(findings)
    return result
