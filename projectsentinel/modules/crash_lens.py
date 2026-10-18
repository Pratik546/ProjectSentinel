"""Parse text logs without claiming root cause certainty."""
from ..models import FileRecord, Finding
from ..adapters.crash import import_crash_logs

def analyze(files: list[FileRecord], **_: object) -> list[Finding]:
    return import_crash_logs(files).findings

def crash_lens(files: list[FileRecord]) -> list[Finding]: return analyze(files)
