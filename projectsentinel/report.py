"""Portable JSON and escaped HTML exports."""
import html, json
from .models import ScanResult
from .security import redact
from .scoring import release_gate, severity_counts

def to_dict(result: ScanResult) -> dict:
    return {"schema_version":"1.0", "project_name": result.root.name, "scan_timestamp": result.started_at,
            "enabled_modules": result.module_status, "project_types": result.project_types, "summary":{"scan_id":result.metadata.get("scan_id"),"files_inspected":len(result.files),"files_skipped":len(result.skipped),"duration_seconds":result.duration_seconds,"risk_score":result.score,"severity_counts":severity_counts(result.findings),"release_gate":release_gate(result)},
            "findings":[{**f.to_dict(),"message":redact(f.message),"evidence":redact(f.evidence or "")} for f in result.findings], "errors":[redact(e) for e in result.errors], "skipped":result.skipped,
            "limitations":["This is an automated audit, not a security certification.","Local dependency parsing does not query vulnerability advisories.","Heuristics and missing evidence require human review."]}

def json_report(result: ScanResult) -> str: return json.dumps(to_dict(result), indent=2, sort_keys=True) + "\n"

def html_report(result: ScanResult) -> str:
    data=to_dict(result); rows=[]
    for f in data["findings"]:
        loc=f["path"] + ((":"+str(f["line"])) if f.get("line") else "")
        rows.append(f"<article><h3>{html.escape(f['severity'])} · {html.escape(f['title'])}</h3><p><code>{html.escape(loc or 'project')}</code></p><p>{html.escape(f['message'])}</p><details><summary>Evidence and remediation</summary><pre>{html.escape(f.get('evidence',''))}</pre><p>{html.escape(f.get('remediation',''))}</p></details></article>")
    return "<!doctype html><meta charset='utf-8'><title>ProjectSentinel report</title><style>body{font:16px system-ui;background:#18171d;color:#eee;max-width:1000px;margin:2rem auto;padding:0 1rem}article{border:1px solid #454052;border-radius:8px;padding:1rem;margin:1rem 0}code{color:#c9b8ff}pre{white-space:pre-wrap}</style>" + f"<h1>ProjectSentinel · {html.escape(data['project_name'])}</h1><p>Automated audit, not a security certification. Scanned {html.escape(data['scan_timestamp'])}.</p><h2>Summary</h2><pre>{html.escape(json.dumps(data['summary'], indent=2))}</pre><h2>Findings</h2>" + ("".join(rows) or "<p>No findings.</p>") + "<h2>Limitations</h2><ul>" + "".join(f"<li>{html.escape(x)}</li>" for x in data["limitations"]) + "</ul>"

def markdown_report(result: ScanResult) -> str:
    return "# ProjectSentinel report\n\n**Risk score:** " + str(result.score) + "/100\n\n" + ("\n".join(f"- **{f.severity.name}** `{f.rule_id}` — {f.path or 'project'}: {redact(f.message)}" for f in result.findings) or "No findings.") + "\n"
