"""Portable JSON and escaped HTML exports."""
from __future__ import annotations

import html
import json
from enum import Enum
from pathlib import Path
from typing import Any

from .models import ScanResult
from .security import redact
from .scoring import (
    adapter_statuses,
    generate_verification_plan,
    release_gate,
    severity_counts,
    verification_plan_summary,
)


SCHEMA_VERSION = "1.1"


def _redacted(value: Any) -> Any:
    """Return JSON-safe, recursively redacted report data."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, Path):
        return redact(value.as_posix())
    if isinstance(value, Enum):
        return value.name.title()
    if isinstance(value, dict):
        return {str(key): _redacted(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_redacted(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact(str(value))


def _imported_crash_logs(result: ScanResult) -> list[dict[str, Any]]:
    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    raw = metadata.get("imported_crash_logs", metadata.get("crash_log_imports", []))
    if isinstance(raw, dict):
        raw = [raw]
    return [_redacted(item) for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _execution_receipts(result: ScanResult) -> list[Any]:
    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    raw = metadata.get("verification_receipts", metadata.get("execution_receipts", []))
    if isinstance(raw, dict):
        raw = [raw]
    return [_redacted(item) for item in raw] if isinstance(raw, list) else []

def to_dict(result: ScanResult) -> dict:
    plan = generate_verification_plan(result)
    plan_summary = verification_plan_summary(plan)
    imported_logs = _imported_crash_logs(result)
    execution_receipts = _execution_receipts(result)
    adapters = adapter_statuses(result)
    summary = {
        "scan_id": result.metadata.get("scan_id"),
        "files_inspected": len(result.files),
        "files_skipped": len(result.skipped),
        "duration_seconds": result.duration_seconds,
        "risk_score": result.score,
        "severity_counts": severity_counts(result.findings),
        "release_gate": release_gate(result),
        "verification_plan_count": plan_summary["findings"],
        "verification_check_count": plan_summary["checks"],
        "manual_check_count": plan_summary["manual_checks"],
        "automated_check_count": plan_summary["automated_checks"],
        "automated_checks_available": plan_summary["automated_available"],
        "adapter_count": len(adapters),
        "imported_crash_log_count": len(imported_logs),
        "execution_receipt_count": len(execution_receipts),
    }
    findings = []
    for finding in result.findings:
        value = finding.to_dict()
        value["message"] = redact(finding.message)
        value["evidence"] = redact(finding.evidence or "")
        value["metadata"] = _redacted(value.get("metadata", {}))
        findings.append(value)
    return {
        "schema_version": SCHEMA_VERSION,
        "project_name": result.root.name,
        "scan_timestamp": result.started_at,
        "enabled_modules": _redacted(result.module_status),
        "project_types": _redacted(result.project_types),
        "summary": _redacted(summary),
        "findings": findings,
        "verification_plan": _redacted(plan),
        "adapters": _redacted(adapters),
        "adapter_status": _redacted(adapters),
        "imported_crash_logs": imported_logs,
        "verification_receipts": execution_receipts,
        "errors": [redact(e) for e in result.errors],
        "skipped": _redacted(result.skipped),
        "limitations":[
            "This is an automated audit, not a security certification.",
            "Local dependency parsing does not query vulnerability advisories.",
            "Verification plans describe checks; they do not prove that checks have run.",
            "Heuristics and missing evidence require human review.",
        ],
    }

def json_report(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, sort_keys=True) + "\n"


def _html_check(check: dict[str, Any]) -> str:
    steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in check.get("steps", []))
    command = check.get("command")
    command_html = ""
    if command:
        command_text = " ".join(command) if isinstance(command, list) else str(command)
        command_html = f"<p><b>Adapter command (not run):</b> <code>{html.escape(command_text)}</code></p>"
    available = check.get("available")
    availability = "available through an adapter" if available is True else "not available from the recorded adapters"
    return (
        f"<h4>{html.escape(str(check.get('kind', 'check')).title())}: {html.escape(str(check.get('title', 'Verification check')))}</h4>"
        f"<p><b>Status:</b> {html.escape(str(check.get('status', 'not_run')))} · {html.escape(availability)}</p>"
        f"<ol>{steps}</ol>"
        f"<p><b>Pass criteria:</b> {html.escape(str(check.get('pass_criteria', '')))}</p>"
        f"{command_html}"
    )

def html_report(result: ScanResult) -> str:
    data = to_dict(result)
    rows=[]
    for f in data["findings"]:
        loc=f["path"] + ((":"+str(f["line"])) if f.get("line") else "")
        rows.append(f"<article><h3>{html.escape(f['severity'])} · {html.escape(f['title'])}</h3><p><code>{html.escape(loc or 'project')}</code></p><p>{html.escape(f['message'])}</p><details><summary>Evidence and remediation</summary><pre>{html.escape(f.get('evidence',''))}</pre><p>{html.escape(f.get('remediation',''))}</p></details></article>")
    plan_rows = []
    for item in data["verification_plan"]:
        finding_loc = item.get("path") or "project"
        if item.get("line"):
            finding_loc = f"{finding_loc}:{item['line']}"
        plan_rows.append(
            f"<article><h3>{html.escape(item['priority'])} · {html.escape(item['title'])}</h3>"
            f"<p><code>{html.escape(str(finding_loc))}</code> · {html.escape(item['rule_id'])}</p>"
            f"{_html_check(item['manual'])}{_html_check(item['automated'])}</article>"
        )
    adapter_rows = "".join(
        f"<li><b>{html.escape(str(adapter.get('name', 'adapter')))}</b>: {html.escape(str(adapter.get('status', 'recorded')))}</li>"
        for adapter in data["adapters"]
    ) or "<li>No adapter status was recorded for this scan.</li>"
    crash_rows = "".join(
        f"<li>{html.escape(str(item.get('name', item.get('path', 'imported log'))))} · {html.escape(str(item.get('bytes', 'size not recorded')))} bytes</li>"
        for item in data["imported_crash_logs"]
    ) or "<li>No external crash logs were imported.</li>"
    receipt_rows = "".join(
        f"<li><b>{html.escape(str(item.get('status', 'recorded')))}</b>"
        f"{(': ' + html.escape(str(item.get('reason', item.get('error', ''))))) if item.get('reason', item.get('error')) else ''}</li>"
        for item in data["verification_receipts"] if isinstance(item, dict)
    ) or "<li>No verification execution receipt was recorded.</li>"
    return (
        "<!doctype html><meta charset='utf-8'><title>ProjectSentinel report</title>"
        "<style>body{font:16px system-ui;background:#18171d;color:#eee;max-width:1000px;margin:2rem auto;padding:0 1rem}article{border:1px solid #454052;border-radius:8px;padding:1rem;margin:1rem 0}code{color:#c9b8ff}pre{white-space:pre-wrap}li{margin:.35rem 0}.notice{color:#c9b8ff}</style>"
        + f"<h1>ProjectSentinel · {html.escape(data['project_name'])}</h1><p>Automated audit, not a security certification. Scanned {html.escape(data['scan_timestamp'])}.</p>"
        + f"<h2>Summary</h2><pre>{html.escape(json.dumps(data['summary'], indent=2))}</pre>"
        + "<h2>Adapter status</h2><ul>" + adapter_rows + "</ul>"
        + "<h2>Imported crash logs</h2><ul>" + crash_rows + "</ul>"
        + "<h2>Verification receipts</h2><ul>" + receipt_rows + "</ul>"
        + "<h2>Findings</h2>" + ("".join(rows) or "<p>No findings.</p>")
        + "<h2>Verification plan</h2><p class='notice'>Checks are proposed from retained evidence. No check is reported as passed unless an external receipt is attached.</p>"
        + ("".join(plan_rows) or "<p>No verification checks are needed for this scan.</p>")
        + "<h2>Limitations</h2><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in data["limitations"]) + "</ul>"
    )

def markdown_report(result: ScanResult) -> str:
    plan = generate_verification_plan(result)
    lines = ["# ProjectSentinel report", "", f"**Risk score:** {result.score}/100", "", "## Findings"]
    lines.append("\n".join(f"- **{f.severity.name}** `{f.rule_id}` — {f.path or 'project'}: {redact(f.message)}" for f in result.findings) or "No findings.")
    lines.extend(["", "## Verification plan"])
    for item in plan:
        lines.append(f"- **{item['priority']}** `{item['rule_id']}` at `{item['path'] or 'project'}`")
        for check in item["checks"]:
            lines.append(f"  - **{check['kind'].title()}** {check['title']} — {check['status']}")
    return "\n".join(lines) + "\n"
