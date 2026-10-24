"""JSON and self-contained HTML audit reports."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import SEVERITY_ORDER, ScanResult, sorted_findings

_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6570;--line:#d8dde3;--card:#f6f8fa;
--crit:#8b1a1a;--high:#b42318;--med:#b54708;--low:#175cd3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--fg:#e6e9ed;--muted:#9aa5b1;
--line:#2b333b;--card:#171d23;--crit:#ff8a8a;--high:#ff9b8f;--med:#ffc27a;--low:#8ab4ff}}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1050px;margin:auto}h1{margin:0 0 4px;font-size:24px}
.sub{color:var(--muted);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card b{display:block;font-size:26px}.card span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.sev{font-weight:700}.Critical{color:var(--crit)}.High{color:var(--high)}
.Medium{color:var(--med)}.Low{color:var(--low)}
.small{color:var(--muted);font-size:13px}
@media (max-width:700px){th:nth-child(5),td:nth-child(5){display:none}}
"""


def write_json(result: ScanResult, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return out


def _e(value: object) -> str:
    return html.escape(str(value))


def write_html(result: ScanResult, path: str | Path) -> Path:
    counts = result.severity_counts
    cards = [
        ("Resources scanned", result.total_resources),
        ("Findings", len(result.findings)),
        ("Risk score (0-100)", result.risk_score),
        ("Resources compliant", f"{result.compliance_rate}%"),
    ] + [(f"{s} findings", counts[s]) for s in SEVERITY_ORDER]

    cards_html = "".join(
        f'<div class="card"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in cards
    )
    scanned = ", ".join(f"{_e(k)}: {v}" for k, v in result.resources_scanned.items())

    rows = []
    for f in sorted_findings(result.findings):
        rows.append(
            "<tr>"
            f'<td class="sev {_e(f.severity)}">{_e(f.severity)}</td>'
            f"<td>{_e(f.cis_control)}</td>"
            f"<td><b>{_e(f.title)}</b><br><span class=small>{_e(f.description)}</span></td>"
            f"<td>{_e(f.service)}<br><span class=small>{_e(f.region)}</span></td>"
            f"<td>{_e(f.resource)}</td>"
            f"<td>{_e(f.remediation)}</td>"
            "</tr>"
        )
    table = (
        "<table><thead><tr><th>Severity</th><th>CIS</th><th>Finding</th><th>Service</th>"
        "<th>Resource</th><th>Remediation</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else "<p>No findings. All scanned resources passed the implemented checks.</p>"
    )
    errors = (
        "<h2>Scan errors</h2><ul>" + "".join(f"<li>{_e(e)}</li>" for e in result.errors) + "</ul>"
        if result.errors
        else ""
    )

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudGuard Audit Report</title><style>{_CSS}</style></head>
<body><main>
<h1>CloudGuard Audit Report</h1>
<div class="sub">Account {_e(result.account_id)} · Regions {_e(", ".join(result.regions))} ·
{_e(result.started_at.strftime("%Y-%m-%d %H:%M UTC"))} · CIS AWS Foundations Benchmark v3.0.0 controls</div>
<div class="cards">{cards_html}</div>
<p class="small">Resources by service — {scanned}</p>
<h2>Findings</h2>{table}{errors}
<p class="small">Risk score weights findings (Critical 10, High 7, Medium 4, Low 1) against the
scan size. It is a prioritisation aid, not a certification of compliance.</p>
</main></body></html>"""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return out
