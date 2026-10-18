"""Local-only conservative secret, configuration and dependency checks."""
import re
from ..models import FileRecord, Finding, Severity, Confidence
from ..security import redact
from ..parsers import parse_requirements
from ._util import finding

SECRET = re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|password|private[_-]?key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
AWS = re.compile(r"AKIA[0-9A-Z]{16}")

def analyze(files: list[FileRecord], **_: object) -> list[Finding]:
    out=[]
    for f in files:
        if not f.text: continue
        name=f.path.lower()
        for no,line in enumerate(f.text.splitlines(),1):
            match=SECRET.search(line) or AWS.search(line)
            if match and not any(x in line.lower() for x in ("example", "placeholder", "changeme", "dummy", "test_")):
                out.append(finding("TRUST-SECRET", "Possible committed credential", Severity.HIGH, f.path, "A credential-like assignment was detected and redacted.", no, redact(line), module="TrustTrail", confidence=Confidence.MEDIUM, why="Credentials committed to a repository can be copied or misused.", remediation="Revoke and rotate the credential if real, remove it from source, and use an ignored secret store."))
        if name.endswith("/.env") or name == ".env":
            out.append(finding("TRUST-ENV", "Environment file is included in the scan", Severity.MEDIUM, f.path, "An .env file may contain deployment secrets; values are not shown.", module="TrustTrail", confidence=Confidence.HIGH, remediation="Keep local .env files out of version control and commit a redacted example instead."))
        if name.endswith(("requirements.txt", "requirements-dev.txt")):
            for dep in parse_requirements(f.text):
                if not re.search(r"(?:==|~=|>=|<=|>|<)\s*[0-9]", dep):
                    out.append(finding("TRUST-UNPINNED", "Dependency version is not pinned", Severity.LOW, f.path, f"Dependency '{dep}' has no reliably extractable version constraint.", module="TrustTrail", confidence=Confidence.HIGH, remediation="Pin direct dependencies using a reviewed lock workflow for reproducible builds."))
    if not any(f.path.endswith(("requirements.txt", "pyproject.toml", "package-lock.json")) for f in files):
        out.append(finding("TRUST-AUDIT-LIMIT", "Dependency vulnerability intelligence was not checked", Severity.INFO, "", "ProjectSentinel performs local parsing only and has no advisory database or network access.", module="TrustTrail", confidence=Confidence.HIGH, actionable=False, remediation="Review dependencies against an authorized advisory source as a separate release step."))
    return out

def trust_trail(files: list[FileRecord]) -> list[Finding]: return analyze(files)
