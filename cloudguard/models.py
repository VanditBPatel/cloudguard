"""Shared data models."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}


@dataclass
class Finding:
    check_id: str
    cis_control: str  # CIS AWS Foundations Benchmark v3.0.0 control number
    title: str
    service: str  # S3 | IAM | EC2 | EBS
    resource: str
    severity: str
    description: str
    remediation: str
    region: str = "global"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    account_id: str
    regions: list[str]
    resources_scanned: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_resources(self) -> int:
        return sum(self.resources_scanned.values())

    @property
    def severity_counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in SEVERITY_ORDER}

    @property
    def risk_score(self) -> int:
        """0 (clean) .. 100 (worst): weighted findings vs. a ceiling set by scan size."""
        if self.total_resources == 0:
            return 0
        raw = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        ceiling = SEVERITY_WEIGHT["High"] * self.total_resources
        return min(100, round(100 * raw / ceiling))

    @property
    def compliance_rate(self) -> int:
        """Share of scanned resources with no findings, as a percentage."""
        if self.total_resources == 0:
            return 100
        bad = len({(f.service, f.resource) for f in self.findings})
        return round(100 * (self.total_resources - bad) / self.total_resources)

    def to_dict(self) -> dict:
        return {
            "account_id": self.account_id,
            "regions": self.regions,
            "scanned_at": self.started_at.isoformat(),
            "resources_scanned": self.resources_scanned,
            "total_resources": self.total_resources,
            "finding_count": len(self.findings),
            "severity_counts": self.severity_counts,
            "risk_score": self.risk_score,
            "compliance_rate": self.compliance_rate,
            "errors": self.errors,
            "findings": [f.to_dict() for f in sorted_findings(self.findings)],
        }


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.service, f.resource)
    )
