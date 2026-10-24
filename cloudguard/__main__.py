"""CLI: python -m cloudguard [--profile NAME] [--regions r1 r2] [--out DIR] | --demo"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import SEVERITY_ORDER, sorted_findings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cloudguard",
        description="Read-only AWS compliance scanner mapped to CIS AWS Foundations Benchmark.",
    )
    p.add_argument("--profile", help="AWS named profile (default: standard credential chain)")
    p.add_argument("--regions", nargs="+", help="Regions to scan for EC2/EBS (default: session region)")
    p.add_argument("--out", default="cloudguard_output", help="Output directory")
    p.add_argument("--include-root", action="store_true",
                   help="Also check root access keys / MFA (needs iam:GetAccountSummary)")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER,
                   help="Exit with code 1 if any finding is at or above this severity (for CI)")
    p.add_argument("--demo", action="store_true",
                   help="Scan a mocked, deliberately misconfigured AWS account (no real AWS calls)")
    return p


def _print_summary(result) -> None:
    counts = result.severity_counts
    print(f"Account {result.account_id} | resources scanned: {result.total_resources} "
          f"({', '.join(f'{k} {v}' for k, v in result.resources_scanned.items())})")
    print(f"Findings: {len(result.findings)}  " +
          "  ".join(f"{s}: {counts[s]}" for s in SEVERITY_ORDER))
    print(f"Risk score: {result.risk_score}/100 | compliant resources: {result.compliance_rate}%\n")
    for f in sorted_findings(result.findings):
        print(f"[{f.severity:<8}] CIS {f.cis_control:<6} {f.service:<4} {f.resource}\n"
              f"           {f.title}")
    for err in result.errors:
        print(f"! scan error: {err}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out = Path(args.out)

    if args.demo:
        from .demo import run_demo

        result = run_demo(str(out))
    else:
        import boto3

        from .report import write_html, write_json
        from .scanner import scan

        session = boto3.session.Session(profile_name=args.profile)
        regions = args.regions or [session.region_name or "us-east-1"]
        try:
            result = scan(session, regions, include_root=args.include_root)
        except RuntimeError as exc:
            print(exc, file=sys.stderr)
            return 2
        write_json(result, out / "cloudguard_report.json")
        write_html(result, out / "cloudguard_report.html")

    _print_summary(result)
    print(f"\nReports written to {out.resolve()}")

    if args.fail_on:
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) <= limit for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
