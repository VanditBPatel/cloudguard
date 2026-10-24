"""EC2 security group checks: open admin ports (CIS 5.2 IPv4 / 5.3 IPv6)."""

from __future__ import annotations

from ..models import Finding

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


def _covers_port(perm: dict, port: int) -> bool:
    proto = perm.get("IpProtocol")
    if proto == "-1":  # all protocols and ports
        return True
    if proto not in {"tcp", "6"}:
        return False
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if lo is None or hi is None:
        return True
    return lo <= port <= hi


def run(session, regions):
    findings: list[Finding] = []
    count = 0
    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        groups = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            groups.extend(page["SecurityGroups"])
        count += len(groups)

        for sg in groups:
            exposed: dict[str, list[str]] = {}
            for perm in sg.get("IpPermissions", []):
                v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
                if not (v4 or v6):
                    continue
                for port, label in ADMIN_PORTS.items():
                    if _covers_port(perm, port):
                        for flag, cis in ((v4, "5.2"), (v6, "5.3")):
                            if flag:
                                exposed.setdefault(cis, []).append(f"{label}/{port}")

            for cis, ports in exposed.items():
                family = "0.0.0.0/0" if cis == "5.2" else "::/0"
                findings.append(
                    Finding(
                        "EC2-001" if cis == "5.2" else "EC2-002",
                        cis,
                        f"Security group allows {family} to remote administration ports",
                        "EC2",
                        f"{sg['GroupId']} ({sg['GroupName']})",
                        "High",
                        f"Ingress from {family} is allowed on {', '.join(sorted(set(ports)))}, "
                        "exposing remote administration to the whole internet.",
                        "Restrict the rule to trusted CIDR ranges, a VPN or a bastion host, "
                        "or use SSM Session Manager instead of open ports.",
                        region,
                    )
                )
    return count, findings
