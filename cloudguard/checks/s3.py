"""S3 checks: public access (CIS 2.1.4) and deny-HTTP policy (CIS 2.1.1)."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..models import Finding

_PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _block_public_access_complete(s3, bucket: str) -> bool:
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return False
        raise
    return all(
        cfg.get(k, False)
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )


def _acl_is_public(s3, bucket: str) -> bool:
    acl = s3.get_bucket_acl(Bucket=bucket)
    return any(
        g.get("Grantee", {}).get("URI") in _PUBLIC_GRANTEES for g in acl.get("Grants", [])
    )


def _policy_is_public(s3, bucket: str) -> bool:
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]
        return bool(status.get("IsPublic"))
    except ClientError as exc:
        if _code(exc) in {"NoSuchBucketPolicy", "NotImplemented"}:
            return False
        raise


def _denies_http(s3, bucket: str) -> bool:
    try:
        doc = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if _code(exc) == "NoSuchBucketPolicy":
            return False
        raise
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for st in statements:
        if st.get("Effect") != "Deny":
            continue
        cond = st.get("Condition", {})
        for op in ("Bool", "BoolIfExists"):
            val = cond.get(op, {}).get("aws:SecureTransport")
            if str(val).lower() == "false":
                return True
    return False


def run(session, regions):  # noqa: ARG001 - S3 listing is global
    s3 = session.client("s3")
    findings: list[Finding] = []
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    for name in buckets:
        pab_ok = _block_public_access_complete(s3, name)
        public = _acl_is_public(s3, name) or _policy_is_public(s3, name)

        if public:
            findings.append(
                Finding(
                    "S3-001",
                    "2.1.4",
                    "S3 bucket is publicly accessible",
                    "S3",
                    name,
                    "High",
                    "The bucket ACL or bucket policy grants access to everyone"
                    + ("" if not pab_ok else " (Block Public Access is on but ACL/policy still public)")
                    + ".",
                    "Enable all four Block Public Access settings and remove public grants "
                    "from the ACL and bucket policy.",
                )
            )
        elif not pab_ok:
            findings.append(
                Finding(
                    "S3-002",
                    "2.1.4",
                    "S3 Block Public Access is not fully enabled",
                    "S3",
                    name,
                    "Medium",
                    "One or more of the four Block Public Access settings is disabled, "
                    "so the bucket could be made public by a later change.",
                    "Enable BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and "
                    "RestrictPublicBuckets on the bucket.",
                )
            )

        if not _denies_http(s3, name):
            findings.append(
                Finding(
                    "S3-003",
                    "2.1.1",
                    "S3 bucket policy does not deny HTTP requests",
                    "S3",
                    name,
                    "Medium",
                    "No bucket policy statement denies requests where aws:SecureTransport "
                    "is false, so data can be requested over unencrypted HTTP.",
                    "Add a Deny statement with Condition Bool aws:SecureTransport = false.",
                )
            )
    return len(buckets), findings
