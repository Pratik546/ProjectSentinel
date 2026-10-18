"""Safe crash/log import and evidence normalization."""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Iterable

from ..models import Confidence, FileRecord, Finding, Severity
from ..security import read_bounded, redact
from ._common import make_finding
from .types import CrashImportResult, CrashLogRecord

ERROR = re.compile(r"\b(?:error|exception|fatal|traceback|assert(?:ion)?|panic|crash)\b", re.I)
LOC = re.compile(r'(?:File "([^"]+)", line (\d+)|([\w./\\-]+):(\d+))')
CRASH_SUFFIXES = frozenset({".log", ".trace", ".crash", ".ips"})
CRASH_TEXT_MARKERS = ("log", "crash", "trace", "stack", "exception", "dump")


def _is_crash_log(record: FileRecord) -> bool:
    """Accept explicit log/crash artifacts, not arbitrary source or docs."""
    path = record.path.replace("\\", "/").lower()
    name = Path(path).name
    suffix = Path(name).suffix
    return (
        suffix in CRASH_SUFFIXES
        or name.endswith(".dmp.txt")
        or (suffix == ".txt" and any(marker in name for marker in CRASH_TEXT_MARKERS))
        or bool(record.metadata.get("crash_log"))
    )


def _format(record: FileRecord) -> str:
    text = (record.text or "").lower()
    if "fatal exception" in text or "logcat" in text:
        return "android-logcat"
    if "exception type:" in text or record.path.lower().endswith(".ips"):
        return "apple-crash"
    if "unityplayer" in text or "unityengine" in text:
        return "unity"
    if "loginit" in text or "unrealbuildtool" in text or "packagingresults" in text:
        return "unreal"
    if "traceback (most recent call last)" in text:
        return "python"
    return "generic"


def _records(files: Iterable[FileRecord]) -> tuple[list[CrashLogRecord], list[Finding]]:
    logs: list[CrashLogRecord] = []
    findings: list[Finding] = []
    for record in files:
        text = record.text
        if not text or not _is_crash_log(record):
            continue
        groups: Counter[str] = Counter()
        first_line: dict[str, int] = {}
        for number, line in enumerate(text.splitlines(), 1):
            if not ERROR.search(line):
                continue
            signature = re.sub(r"0x[0-9a-f]+|\d+|[A-Za-z]:[\\/][^ ]+", "<value>", line.strip(), flags=re.I)[:180]
            signature = redact(signature)
            groups[signature] += 1
            first_line.setdefault(signature, number)
        if not groups:
            continue
        format_name = _format(record)
        logs.append(CrashLogRecord(record.path, format_name, tuple(groups), sum(groups.values()), min(first_line.values())))
        location = LOC.search(text)
        for signature, count in groups.most_common():
            generated = record.path.lower().startswith(("logs/", ".utmp/"))
            severity = Severity.MEDIUM if generated else Severity.HIGH if any(word in signature.lower() for word in ("fatal", "exception", "panic", "crash")) else Severity.MEDIUM
            findings.append(
                make_finding(
                    "CRASH-ERROR",
                    "Repeated log error",
                    severity,
                    record.path,
                    f"Observed {count} occurrence(s) of a normalized error signature in a {format_name} log. Root cause is not established from logs alone.",
                    line=first_line[signature],
                    evidence=signature,
                    module="CrashLens",
                    confidence=Confidence.MEDIUM if generated else Confidence.HIGH,
                    why="Repeated errors are evidence of a release risk or diagnosability gap.",
                    remediation="Reproduce the error in the relevant engine/toolchain, inspect the surrounding stack trace, and add a regression test if the issue affects the shipped app.",
                    metadata={"signature": signature, "occurrences": count, "log_format": format_name, "generated_artifact": generated, "candidate_location": location.group(0) if location else None, "root_cause_claim": False},
                )
            )
    return logs, findings


def import_crash_logs(source: Iterable[FileRecord | str | Path] | str | Path, *, max_bytes: int = 2_000_000) -> CrashImportResult:
    """Import text logs from existing scan records or explicit local paths."""
    candidates = [source] if isinstance(source, (str, Path)) else list(source)
    records: list[FileRecord] = []
    for candidate in candidates:
        if isinstance(candidate, FileRecord):
            records.append(candidate)
            continue
        path = Path(candidate)
        if path.is_symlink() or not path.is_file():
            continue
        try:
            data = read_bounded(path, max_bytes)
            text = data.decode("utf-8", errors="replace")
            records.append(FileRecord(path.name, len(data), "", text, {}, None))
        except (OSError, ValueError):
            continue
    logs, findings = _records(records)
    return CrashImportResult(
        adapter="crash",
        state="inspected" if logs else "not_applicable",
        findings=findings,
        evidence={"logs": [log.path for log in logs], "records": len(logs)},
        logs=tuple(logs),
        limitations=["Log signatures are evidence only; stack traces and timestamps do not prove root cause."],
    )


def analyze(files: list[FileRecord]) -> list[Finding]:
    return import_crash_logs(files).findings


import_logs = import_crash_logs
