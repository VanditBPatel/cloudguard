import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from cloudguard import demo  # noqa: E402
from cloudguard.checks.iam import _is_full_admin  # noqa: E402
from cloudguard.scanner import scan  # noqa: E402


def _scan_demo():
    demo._fake_credentials()
    with mock_aws():
        session = boto3.session.Session(region_name=demo.REGION)
        demo.populate(session)
        return scan(session, [demo.REGION])


def test_demo_resource_and_finding_totals():
    r = _scan_demo()
    assert r.errors == []
    assert r.total_resources == 13
    assert len(r.findings) == 7
    assert r.severity_counts["High"] == 3
    assert r.severity_counts["Medium"] == 4


def test_expected_checks_fire_on_expected_resources():
    r = _scan_demo()
    got = Counter((f.check_id, f.resource) for f in r.findings)
    assert got[("S3-001", "demo-public-assets")] == 1
    assert got[("S3-003", "demo-public-assets")] == 1
    assert got[("S3-003", "demo-app-backups")] == 1
    assert got[("IAM-001", "alice.analyst")] == 1
    assert got[("IAM-002", "DemoFullAdmin")] == 1
    assert sum(1 for f in r.findings if f.check_id == "EC2-001") == 1
    assert sum(1 for f in r.findings if f.check_id == "EBS-001") == 1


def test_hardened_resources_are_clean():
    r = _scan_demo()
    flagged = {f.resource for f in r.findings}
    assert "demo-secure-logs" not in flagged
    assert "DemoS3ReadOnly" not in flagged
    assert "svc-deploy" not in flagged


def test_full_admin_detection():
    assert _is_full_admin({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    assert _is_full_admin({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}})
    assert not _is_full_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    assert not _is_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})


def test_reports_are_written(tmp_path):
    result = demo.run_demo(str(tmp_path))
    assert (tmp_path / "cloudguard_report.json").exists()
    html = (tmp_path / "cloudguard_report.html").read_text()
    assert "CloudGuard Audit Report" in html
    assert len(result.findings) == 7
