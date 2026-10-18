"""Requirements and release evidence checks."""
import json
from pathlib import Path
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding

def load_requirements(source: str | Path | None) -> tuple[dict | None, str | None]:
    if not source: return None, None
    try:
        raw = Path(source).read_text(encoding="utf-8") if isinstance(source, (str, Path)) and Path(source).exists() else str(source)
        data=json.loads(raw)
        if not isinstance(data, dict) or not isinstance(data.get("requirements"), list): return None, "requirements must be an object containing a requirements array"
        for item in data["requirements"]:
            if not isinstance(item, dict) or not item.get("id") or not item.get("description"): return None, "each requirement needs id and description"
        return data, None
    except (OSError, json.JSONDecodeError) as exc: return None, str(exc)

def analyze(files: list[FileRecord], *, requirements: str | Path | None = None, **_: object) -> list[Finding]:
    out=[]
    data, error=load_requirements(requirements)
    if error: out.append(finding("SCOPE-SCHEMA", "Requirements file is invalid", Severity.MEDIUM, "", error, module="ScopeGuard", confidence=Confidence.HIGH, remediation="Fix the JSON schema: provide a requirements array with id and description."))
    if data:
        for item in data["requirements"]:
            status=str(item.get("status", "unverified")).lower()
            if status not in {"passed", "verified", "complete"}:
                out.append(finding("SCOPE-UNVERIFIED", f"Requirement remains {status}", Severity.MEDIUM if status=="blocked" else Severity.LOW, "", item["description"], module="ScopeGuard", confidence=Confidence.HIGH, remediation="Perform the stated verification and attach a test or manual evidence reference.", metadata={"requirement_id": item["id"], "category": item.get("category", "uncategorized"), "status": status}))
    checks = [("tests", any(f.path.startswith(("tests/", "test/")) for f in files)), ("lockfile", any(Path(f.path).name in {"requirements-lock.txt", "poetry.lock", "package-lock.json"} for f in files)), ("documentation", any(Path(f.path).name.lower() in {"readme.md", "readme.rst"} for f in files))]
    for label, ok in checks:
        if not ok: out.append(finding("SCOPE-RELEASE", f"Release evidence missing: {label}", Severity.INFO, "", "Automated presence check only; this does not prove release readiness.", module="ScopeGuard", confidence=Confidence.HIGH, actionable=False, remediation=f"Add or document the {label} release check."))
    return out

def scope_guard(files: list[FileRecord]) -> list[Finding]: return analyze(files)
