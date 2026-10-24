"""IAM checks: console users without MFA (CIS 1.10), full-admin policies (CIS 1.16),
root access keys and root MFA (CIS 1.4 / 1.5)."""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Finding


def _as_list(value):
    return value if isinstance(value, list) else [value]


def _is_full_admin(document: dict) -> bool:
    """True if any Allow statement grants Action '*' on Resource '*'."""
    for st in _as_list(document.get("Statement", [])):
        if st.get("Effect") != "Allow" or "NotAction" in st or "NotResource" in st:
            continue
        actions = _as_list(st.get("Action", []))
        resources = _as_list(st.get("Resource", []))
        if "*" in actions and "*" in resources:
            return True
    return False


def _console_users_without_mfa(iam) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    users = []
    for page in iam.get_paginator("list_users").paginate():
        users.extend(page["Users"])

    for user in users:
        name = user["UserName"]
        try:
            iam.get_login_profile(UserName=name)
            has_console = True
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
            has_console = False
        if not has_console:
            continue
        if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
            findings.append(
                Finding(
                    "IAM-001",
                    "1.10",
                    "IAM user with console password has no MFA",
                    "IAM",
                    name,
                    "Medium",
                    "The user can sign in to the console with a password only, so a "
                    "stolen or guessed password gives full access to the user's permissions.",
                    "Register a virtual or hardware MFA device for the user, or remove the "
                    "console password.",
                )
            )
    return len(users), findings


def _admin_policies(iam) -> tuple[int, list[Finding]]:
    findings: list[Finding] = []
    policies = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        policies.extend(page["Policies"])

    for pol in policies:
        version = iam.get_policy_version(
            PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
        )["PolicyVersion"]["Document"]
        if _is_full_admin(version):
            attached = pol.get("AttachmentCount", 0)
            findings.append(
                Finding(
                    "IAM-002",
                    "1.16",
                    "IAM policy allows full '*:*' administrative privileges",
                    "IAM",
                    pol["PolicyName"],
                    "High",
                    "The customer-managed policy allows all actions on all resources "
                    f"(currently attached to {attached} identity(ies)).",
                    "Replace the wildcard with the specific actions and resources required "
                    "(least privilege) and detach the policy where not needed.",
                )
            )
    return len(policies), findings


def _root_checks(iam) -> list[Finding]:
    findings: list[Finding] = []
    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except ClientError:
        return findings
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append(
            Finding(
                "IAM-003",
                "1.4",
                "Root account has an access key",
                "IAM",
                "root",
                "High",
                "Root access keys give unrestricted programmatic access and cannot be "
                "limited by IAM policy.",
                "Delete the root access keys and use IAM roles or users instead.",
            )
        )
    if summary.get("AccountMFAEnabled", 1) == 0:
        findings.append(
            Finding(
                "IAM-004",
                "1.5",
                "MFA is not enabled for the root account",
                "IAM",
                "root",
                "High",
                "The root user can only be protected from credential theft by MFA.",
                "Enable a hardware or virtual MFA device for the root user.",
            )
        )
    return findings


def run(session, regions, include_root: bool = False):  # noqa: ARG001
    iam = session.client("iam")
    users_count, f1 = _console_users_without_mfa(iam)
    pol_count, f2 = _admin_policies(iam)
    findings = f1 + f2
    if include_root:
        findings += _root_checks(iam)
    return users_count + pol_count, findings
