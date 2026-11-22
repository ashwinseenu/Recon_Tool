"""Report rendering (JSON / HTML / Markdown / CSV) and the on-disk report store.

Renderers work on the report *dict* (the JSON form), so a report can be
re-exported later from disk exactly as it was produced.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core import paths
from ..core.models import SEVERITY_ORDER, ScanReport

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
                   autoescape=select_autoescape(["html"]))


def all_findings(rep: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for m in rep["modules"]:
        for f in m["findings"]:
            out.append({**f, "module": m["module"]})
    return sorted(out, key=lambda f: -SEVERITY_ORDER[f["severity"]])


def _ts(value: Optional[float]) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def render_html(rep: Dict[str, Any]) -> str:
    findings = all_findings(rep)
    return _env.get_template("report.html").render(
        rep=rep, findings=findings, notable=[f for f in findings if f["severity"] != "info"],
        started=_ts(rep.get("started_at")), order=list(SEVERITY_ORDER))


def render_markdown(rep: Dict[str, Any]) -> str:
    sc = rep["severity_counts"]
    lines = [f"# ReconForge report: {rep['target']}", "",
             f"- Scan: `{rep['scan_id']}`  |  Started: {_ts(rep.get('started_at'))}  |  Duration: {rep['duration']}s",
             f"- Egress: {rep['egress'].get('mode')} / {rep['egress'].get('egress_ip')} / tor={rep['egress'].get('is_tor')}",
             f"- Scope: {rep['scope']}",
             "- Severity: " + ", ".join(f"{k} {v}" for k, v in sc.items() if v), "", "## Findings (non-informational)", ""]
    notable = [f for f in all_findings(rep) if f["severity"] != "info"]
    if not notable:
        lines.append("_No findings above informational severity._")
    for f in notable:
        lines += [f"### [{f['severity'].upper()}] {f['title']}", f"*{f['module']}*" + (f" - `{f['host']}`" if f["host"] else ""), ""]
        if f["detail"]:
            lines += [f["detail"], ""]
        if f["remediation"]:
            lines += [f"**Fix:** {f['remediation']}", ""]
    lines += ["## Assets", "", f"- Hostnames: {len(rep['assets'].get('hostnames', []))}",
              f"- IPs: {len(rep['assets'].get('ips', []))}", ""]
    for h in rep["assets"].get("hostnames", []):
        lines.append(f"- {h['host']} ({', '.join(h['sources'])})")
    lines += ["", "## Modules", "", "| Module | Status | Findings | Time |", "|---|---|---|---|"]
    for m in rep["modules"]:
        status = "skipped: " + m["skip_reason"] if m["skipped"] else ("error: " + m["error"] if not m["ok"] else "ok")
        lines.append(f"| {m['module']} | {status} | {len(m['findings'])} | {m['duration']}s |")
    return "\n".join(lines) + "\n"


def render_csv(rep: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "module", "host", "title", "detail", "remediation"])
    for f in all_findings(rep):
        w.writerow([f["severity"], f["module"], f["host"], f["title"], f["detail"], f["remediation"]])
    return buf.getvalue()


RENDERERS = {"json": lambda r: json.dumps(r, indent=2), "html": render_html, "md": render_markdown, "csv": render_csv}


def write_report(report: ScanReport, formats: List[str]) -> Dict[str, Path]:
    rep = report.to_dict()
    out: Dict[str, Path] = {}
    for fmt in dict.fromkeys(["json", *formats]):
        if fmt not in RENDERERS:
            continue
        p = paths.results_dir() / f"{rep['scan_id']}.{fmt}"
        p.write_text(RENDERERS[fmt](rep), encoding="utf-8")
        p.chmod(0o600)
        out[fmt] = p
    return out


# -- store -----------------------------------------------------------------------

def valid_id(scan_id: str) -> bool:
    return bool(_ID_RE.match(scan_id)) and ".." not in scan_id


def load_report(scan_id: str) -> Dict[str, Any]:
    if not valid_id(scan_id):
        raise ValueError("invalid scan id")
    p = paths.results_dir() / f"{scan_id}.json"
    if not p.exists():
        raise FileNotFoundError(scan_id)
    return json.loads(p.read_text(encoding="utf-8"))


def list_reports(limit: int = 100) -> List[Dict[str, Any]]:
    rows = []
    for p in sorted(paths.results_dir().glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            rows.append({"scan_id": d["scan_id"], "target": d["target"], "findings": d["finding_count"],
                         "severity": d["severity_counts"], "duration": d["duration"], "started_at": d.get("started_at")})
        except (ValueError, KeyError):
            continue
    return rows
