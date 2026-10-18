import hashlib
from ..models import Confidence, Finding, Severity
from ..security import redact

def finding(rule: str, title: str, severity: Severity, path: str, message: str, line: int | None = None, evidence: str | None = None, *, module: str = "", confidence: Confidence = Confidence.MEDIUM, remediation: str = "Review the evidence and verify the recommended change before release.", why: str = "This evidence may increase release risk.", metadata: dict | None = None, actionable: bool = True) -> Finding:
    canonical = f"{rule}\0{path}\0{line or ''}\0{message}"
    fid = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    return Finding(rule, title, severity, path, redact(message), line, redact(evidence) if evidence else None, fid, module, confidence, why, remediation, actionable, (), metadata or {})
