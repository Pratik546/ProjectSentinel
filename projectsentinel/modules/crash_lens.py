"""Parse text logs without claiming root cause certainty."""
import re
from collections import Counter
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding

ERROR = re.compile(r"\b(?:error|exception|fatal|traceback|assert(?:ion)?)\b", re.I)
LOC = re.compile(r"(?:File \"([^\"]+)\", line (\d+)|([\w./\\-]+):(\d+))")

def analyze(files: list[FileRecord], **_: object) -> list[Finding]:
    out=[]
    for f in files:
        if not f.text or not (f.path.lower().endswith((".log", ".txt", ".trace")) or "traceback" in f.text.lower()): continue
        groups: Counter[str] = Counter()
        first_line: dict[str, int] = {}
        for no, line in enumerate(f.text.splitlines(), 1):
            if ERROR.search(line):
                signature = re.sub(r"\d+|0x[0-9a-f]+|[A-Za-z]:[\\/][^ ]+", "<value>", line.strip(), flags=re.I)[:180]
                groups[signature] += 1; first_line.setdefault(signature, no)
        for sig, count in groups.most_common():
            sev = Severity.HIGH if "fatal" in sig.lower() or "exception" in sig.lower() else Severity.MEDIUM
            loc = LOC.search(f.text)
            out.append(finding("CRASH-ERROR", "Repeated log error", sev, f.path, f"Observed {count} occurrence(s) of a normalized error signature. Root cause is not established from logs alone.", first_line[sig], sig, module="CrashLens", confidence=Confidence.HIGH, why="Repeated errors are evidence of a release risk or diagnosability gap.", remediation="Reproduce the error, inspect the surrounding stack trace, and add a regression test for the observed behavior.", metadata={"signature": sig, "occurrences": count, "candidate_location": (loc.group(0) if loc else None)}))
    return out

def crash_lens(files: list[FileRecord]) -> list[Finding]: return analyze(files)
