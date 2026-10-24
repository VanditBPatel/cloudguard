"""EBS checks: unencrypted volumes (CIS 2.2.1) and account default encryption."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Finding


def run(session, regions):
    findings: list[Finding] = []
    count = 0
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        volumes = []
        for page in ec2.get_paginator("describe_volumes").paginate():
            volumes.extend(page["Volumes"])
        count += len(volumes)

        for vol in volumes:
            if not vol.get("Encrypted"):
                attached = [a["InstanceId"] for a in vol.get("Attachments", [])]
                findings.append(
                    Finding(
                        "EBS-001",
                        "2.2.1",
                        "EBS volume is not encrypted",
                        "EBS",
                        vol["VolumeId"],
                        "Medium",
                        "Data at rest on the volume (and its snapshots) is not encrypted"
                        + (f"; attached to {', '.join(attached)}." if attached else "."),
                        "Create an encrypted copy from a snapshot, replace the volume, and "
                        "enable EBS encryption by default for the region.",
                        region,
                    )
                )
    return count, findings


def default_encryption_status(session, regions) -> dict[str, bool | None]:
    """Informational: is EBS encryption-by-default on, per region? (None = unknown)."""
    status: dict[str, bool | None] = {}
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            status[region] = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        except ClientError:
            status[region] = None
    return status
