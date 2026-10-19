"""Judge-friendly Streamlit UI for the offline ProjectSentinel auditor."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, is_dataclass
import hashlib
import importlib
import json
from pathlib import Path
import os
import sys
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULE_HELP = {
    "SceneSentry": "structure, code, assets, engines, mobile projects, and models",
    "CrashLens": "repeated errors and stack traces in text logs",
    "TrustTrail": "redacted secrets, configuration, and dependency evidence",
    "ScopeGuard": "requirements and release evidence",
}
MODULES = list(MODULE_HELP)
MAX_IMPORTED_CRASH_LOG_BYTES = 5 * 1024 * 1024
WORKSPACE_INTERNAL_IGNORES = {".opencode", ".omnirush", "reports"}


def _default_target() -> str:
    """Return a usable initial project folder for the local app.

    A blank environment variable previously left the scan form empty, so a
    first click on **Scan Project** could only produce the invalid-directory
    error.  The workspace containing ``app.py`` is a real, safe read-only
    project default; an explicitly configured target is preserved so a bad
    configuration remains visible instead of being silently replaced.
    """
    configured = os.getenv("PROJECTSENTINEL_TARGET", "").strip()
    return configured or str(ROOT)


def _effective_ignores(target: str | Path, extra_ignores: set[str]) -> set[str]:
    """Skip app-generated workspace data only when scanning this workspace."""
    ignores = set(extra_ignores)
    try:
        is_workspace = Path(target).expanduser().resolve() == ROOT
    except OSError:
        is_workspace = False
    if is_workspace:
        ignores.update(WORKSPACE_INTERNAL_IGNORES)
    return ignores


def _filtered_findings(result, query: str, severities: list[str], confidences: list[str], modules: list[str]):
    """Return the same finding collection for the table and detail cards."""
    query = query.lower().strip()
    return [
        finding for finding in result.findings
        if (not query or query in " ".join((finding.title, finding.message, finding.path, finding.rule_id)).lower())
        and (not severities or finding.severity.name.title() in severities)
        and (not confidences or finding.confidence.name.title() in confidences)
        and (not modules or finding.module in modules)
    ]


def _requirements_summary(raw: str) -> tuple[int, int, int, str | None]:
    if not raw.strip():
        return 0, 0, 0, None
    try:
        import json
        data = json.loads(raw)
        items = data.get("requirements", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            return 0, 0, 0, "requirements must be an array"
        verified = sum(str(item.get("status", "")).lower() in {"passed", "verified", "complete"} for item in items if isinstance(item, dict))
        blocked = sum(str(item.get("status", "")).lower() == "blocked" for item in items if isinstance(item, dict))
        return verified, len(items) - verified - blocked, blocked, None
    except (ValueError, TypeError, AttributeError) as exc:
        return 0, 0, 0, str(exc)


def _scan_fingerprint(target: str, modules: list[str], max_file_bytes: int, max_files: int, large_file_bytes: int, ignores: set[str], requirements: str) -> str:
    """Identify the exact inputs represented by the visible scan receipt."""
    payload = {
        "target": str(Path(target).expanduser().resolve()),
        "modules": sorted(modules),
        "max_file_bytes": int(max_file_bytes),
        "max_files": int(max_files),
        "large_file_bytes": int(large_file_bytes),
        "ignores": sorted(ignores),
        "requirements": requirements,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _adapter_status_rows(result) -> list[dict[str, Any]]:
    """Expose adapter records emitted by real scanner adapters.

    Adapter status is intentionally not inferred from enabled modules.  A
    module can complete without having a compiler, engine, or advisory source
    available, so the UI only renders records supplied in scan metadata.
    """
    from projectsentinel.scoring import adapter_statuses

    rows = []
    for item in adapter_statuses(result):
        rows.append({
            "Adapter": item.get("name", item.get("id", "unnamed")),
            "Status": item.get("status", "recorded"),
            "Version": item.get("version", "—"),
            "Evidence": item.get("evidence", item.get("detail", "—")),
        })
    return rows


def _record_language_adapter_status(result) -> None:
    """Run read-only adapter discovery so the UI can show real proposals."""
    if result.metadata.get("adapter_status") or result.metadata.get("adapter_statuses"):
        return
    try:
        from projectsentinel.adapters import discover_adapters
        discovery = discover_adapters(result.root, check_executables=True)
    except (ImportError, OSError, ValueError):
        return
    statuses: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    for proposal in discovery.proposals:
        row = {
            "name": proposal.language,
            "status": proposal.status.value,
            "executable": proposal.executable,
            "command": list(proposal.command),
            "reason": proposal.reason,
            "evidence": list(proposal.evidence),
        }
        statuses.append(row)
        if proposal.status.value == "proposed":
            commands.append(row)
    for skipped in discovery.skipped:
        statuses.append({"name": skipped.language, "status": skipped.status.value, "reason": skipped.reason})
    if statuses:
        result.metadata["adapter_status"] = statuses
    if commands:
        result.metadata["adapter_commands"] = commands


def _verification_plan_rows(result) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Flatten the report plan for Streamlit's table while preserving checks."""
    from projectsentinel.scoring import generate_verification_plan, verification_plan_summary

    plan = generate_verification_plan(result)
    rows = []
    for item in plan:
        for check in item.get("checks", []):
            rows.append({
                "Plan": item["plan_id"],
                "Finding": item["title"],
                "Rule": item["rule_id"],
                "Priority": item["priority"],
                "Type": check["kind"].title(),
                "Status": check["status"],
                "Adapter command": "available" if check.get("available") is True else "not recorded",
                "Check": check["title"],
                "Pass criteria": check["pass_criteria"],
            })
    return rows, verification_plan_summary(plan)


def _crash_display_rows(result, minimum_occurrences: int) -> list[dict[str, Any]]:
    """Build a compact, readable CrashLens table from retained findings."""
    rows = []
    for finding in result.findings:
        if finding.rule_id != "CRASH-ERROR" or finding.metadata.get("occurrences", 0) < minimum_occurrences:
            continue
        rows.append({
            "Severity": finding.severity.name.title(),
            "Log path": finding.path or "project",
            "Line": finding.line or "—",
            "Occurrences": finding.metadata.get("occurrences", "—"),
            "Format": finding.metadata.get("log_format", "generic"),
            "Signature": finding.metadata.get("signature", finding.evidence or "—"),
        })
    return rows


def _crash_evidence_payload(result, minimum_occurrences: int) -> dict[str, Any]:
    """Return downloadable, redacted CrashLens evidence without raw log bodies."""
    from projectsentinel.report import to_dict

    data = to_dict(result)
    return {
        "schema_version": data["schema_version"],
        "scan_id": data["summary"].get("scan_id"),
        "minimum_occurrences": minimum_occurrences,
        "imported_crash_logs": data.get("imported_crash_logs", []),
        "findings": [
            finding for finding in data["findings"]
            if finding.get("rule_id") == "CRASH-ERROR"
            and finding.get("metadata", {}).get("occurrences", 0) >= minimum_occurrences
        ],
        "limitations": [
            "Original log bodies are not embedded; retain the source logs separately.",
            "Signatures are evidence and do not establish root cause.",
        ],
    }


def _parse_imported_crash_logs(uploaded_files, *, max_bytes: int = MAX_IMPORTED_CRASH_LOG_BYTES) -> tuple[list[dict[str, Any]], list[Any], list[str]]:
    """Parse user-selected crash logs as bounded, in-memory CrashLens inputs."""
    from projectsentinel.models import FileRecord
    from projectsentinel.security import sha256_bytes

    records = []
    receipts = []
    errors = []
    for uploaded in uploaded_files or []:
        raw_name = str(getattr(uploaded, "name", "crash.log"))
        name = Path(raw_name).name or "crash.log"
        try:
            payload = uploaded.getvalue()
        except (AttributeError, OSError) as exc:
            errors.append(f"{name}: could not read upload: {exc}")
            continue
        if len(payload) > max_bytes:
            errors.append(f"{name}: exceeds the {max_bytes // (1024 * 1024)} MB import limit")
            continue
        text = payload.decode("utf-8", errors="replace")
        record = FileRecord(
            f"imported/{name}",
            len(payload),
            sha256_bytes(payload),
            text,
            {"crash_log": True, "source": "streamlit_upload"},
        )
        records.append(record)
        receipts.append({
            "name": name,
            "path": record.path,
            "bytes": len(payload),
            "sha256": record.sha256,
            "source": "streamlit_upload",
        })
    try:
        # Prefer the richer crash adapter when T2 is present; the original
        # CrashLens parser remains a compatibility fallback for older installs.
        try:
            from projectsentinel.adapters.crash import import_crash_logs
        except ImportError:
            from projectsentinel.modules.crash_lens import analyze
            findings = analyze(records)
        else:
            findings = import_crash_logs(records).findings
    except Exception as exc:  # a malformed imported file must not break the scan UI
        errors.append(f"CrashLens import: {type(exc).__name__}: {exc}")
        findings = []
    for receipt in receipts:
        receipt["findings"] = sum(f.path == receipt["path"] for f in findings)
    return receipts, findings, errors


def _uploaded_crash_payloads(uploaded_files, *, max_bytes: int = MAX_IMPORTED_CRASH_LOG_BYTES) -> dict[str, bytes]:
    """Retain only bounded imported bytes needed for an explicit download."""
    from projectsentinel.security import sha256_bytes

    payloads: dict[str, bytes] = {}
    for uploaded in uploaded_files or []:
        try:
            payload = uploaded.getvalue()
        except (AttributeError, OSError):
            continue
        if len(payload) <= max_bytes:
            payloads[sha256_bytes(payload)] = payload
    return payloads


def _attach_imported_findings(result, findings: list[Any], receipts: list[dict[str, Any]]) -> None:
    """Merge imported findings once, retaining a verifiable receipt in metadata."""
    existing = {finding.finding_id for finding in result.findings}
    result.findings.extend(finding for finding in findings if finding.finding_id not in existing)
    result.findings.sort(key=lambda finding: (-int(finding.severity), -int(finding.confidence), finding.path, finding.rule_id, finding.line or 0))
    imported = result.metadata.setdefault("imported_crash_logs", [])
    if not isinstance(imported, list):
        imported = []
        result.metadata["imported_crash_logs"] = imported
    known = {item.get("sha256") for item in imported if isinstance(item, dict)}
    imported.extend(item for item in receipts if item.get("sha256") not in known)


def _safe_execution_adapter() -> tuple[Any | None, str | None, str | None]:
    """Find an explicitly safe runner supplied by the execution adapter.

    The UI never falls back to ``subprocess``.  If T1's allowlisted runner is
    unavailable, the execution control remains visible but reports that no
    safe executor is connected.
    """
    for module_name in ("projectsentinel.execution", "projectsentinel.runner", "projectsentinel.command_runner"):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        for function_name in ("run_allowlisted", "run_verification", "execute_allowlisted", "run_command"):
            runner = getattr(module, function_name, None)
            if callable(runner):
                return runner, module_name, function_name
    return None, None, None


def _execute_opt_in_check(result, check: dict[str, Any]) -> dict[str, Any]:
    """Execute one adapter command only after the caller enabled the control."""
    command = check.get("command")
    if not command or check.get("available") is not True:
        return {"status": "not_available", "reason": "No adapter-provided command is available for this check."}
    runner, adapter_name, runner_name = _safe_execution_adapter()
    if runner is None:
        return {"status": "not_available", "reason": "No allowlisted execution adapter is connected."}
    try:
        if runner_name == "run_command":
            receipt = runner(command, cwd=str(result.root), timeout_seconds=60, enabled=True)
        else:
            receipt = runner(command, cwd=str(result.root), timeout_seconds=60, opt_in=True)
    except TypeError as exc:
        # Do not retry an execution after an ambiguous adapter failure.  The
        # caller can inspect the receipt and choose whether to try again.
        return {"status": "failed", "adapter": adapter_name, "error": str(exc)}
    except Exception as exc:
        return {"status": "failed", "adapter": adapter_name, "error": str(exc)}
    status = getattr(receipt, "status", None)
    if status is None and isinstance(receipt, dict):
        status = receipt.get("status")
    status = getattr(status, "value", status) or "recorded"
    return {"status": str(status), "adapter": adapter_name, "receipt": receipt}


def _serialise_execution_receipt(receipt: Any) -> Any:
    """Keep optional runner receipts portable for the JSON/HTML report."""
    if is_dataclass(receipt):
        return asdict(receipt)
    if hasattr(receipt, "to_dict") and callable(receipt.to_dict):
        return receipt.to_dict()
    if isinstance(receipt, dict):
        return {str(key): _serialise_execution_receipt(value) for key, value in receipt.items()}
    return {"value": str(receipt)}


def main() -> None:
    try:
        import streamlit as st
    except ImportError as exc:
        raise SystemExit("Install dependencies with: python -m pip install -r requirements-lock.txt") from exc

    from projectsentinel.models import Severity
    from projectsentinel.report import html_report, json_report
    from projectsentinel.scoring import release_gate
    from projectsentinel.scanner import analyze_project

    st.set_page_config(page_title="ProjectSentinel", page_icon="🛡", layout="wide")
    st.markdown(
        """<style>
        .block-container{padding-top:2rem;max-width:1400px}
        [data-testid=stMetric]{background:#25222d;border:1px solid #40384f;padding:1rem;border-radius:8px}
        .hero{background:#211e2a;border:1px solid #51466a;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1rem}
        .step{color:#c9b8ff;font-weight:600}
        </style>""", unsafe_allow_html=True,
    )

    default_target = _default_target()

    st.markdown(
        """<div class="hero"><h1>🛡 ProjectSentinel</h1>
        <p><b>Find what to fix before release.</b> Scan a project locally, inspect file-level evidence, and export a reviewable report.</p>
        <p class="step">1 Choose a project&nbsp;&nbsp; → &nbsp;&nbsp;2 Scan locally&nbsp;&nbsp; → &nbsp;&nbsp;3 Review evidence and export</p>
        </div>""", unsafe_allow_html=True,
    )
    if "target_input" not in st.session_state:
        st.session_state.target_input = default_target

    with st.sidebar:
        st.header("1 · Choose a project")
        target = st.text_input("Project folder (read-only)", key="target_input", help="Use the project root when possible. For Unity, choose the folder containing Assets, Packages, and ProjectSettings.")
        st.caption("Choose the project root when possible. For Unity, use the folder containing Assets, Packages, and ProjectSettings.")

        st.header("2 · Choose checks")
        modules = st.multiselect(
            "Modules to run",
            MODULES,
            default=MODULES,
            format_func=lambda name: f"{name} — {MODULE_HELP[name]}",
        )
        with st.expander("Advanced scan limits", expanded=False):
            max_file_gb = st.number_input(
                "Max file size (GB)",
                min_value=0.01,
                max_value=100.0,
                value=1.0,
                step=0.01,
                format="%.2f",
                help="Files up to this size are included, up to 100 GB. Hashing is streamed; large text/binary bodies are bounded in memory.",
            )
            max_files = st.number_input("Max files", 100, 100000, 100000)
            large_file_gb = st.number_input(
                "Large-file warning threshold (GB)",
                min_value=0.001,
                max_value=10.0,
                value=0.025,
                step=0.001,
                format="%.3f",
                help="0.025 GB is approximately 25 MB. This is a warning threshold, not a skip limit.",
            )
            extra_ignores = st.text_input("Additional folders to skip", placeholder="GeneratedLocalRepo,temp")
        req = st.text_area("Release requirements evidence (optional)", placeholder='{"requirements": []}', height=100)
        run = st.button("Scan Project", type="primary", use_container_width=True)
        st.header("Optional verification inputs")
        execution_opt_in = st.checkbox(
            "Enable opt-in verification execution",
            value=False,
            help="Commands remain disabled until this box and a specific Run button are selected. ProjectSentinel never executes project code during scanning.",
        )
        uploaded_crash_logs = st.file_uploader(
            "Import crash logs (optional)",
            type=["log", "txt", "trace", "crash", "json"],
            accept_multiple_files=True,
            help="Logs are read in memory, bounded, redacted in reports, and passed only to CrashLens.",
        )
        import_crash_logs = st.button("Import selected crash logs", use_container_width=True)
        st.caption("Privacy: local-only, read-only, no API key required.")

    if import_crash_logs:
        receipts, imported_findings, import_errors = _parse_imported_crash_logs(uploaded_crash_logs)
        st.session_state.pending_imported_crash_receipts = receipts
        st.session_state.pending_imported_crash_findings = imported_findings
        st.session_state.pending_imported_crash_payloads = _uploaded_crash_payloads(uploaded_crash_logs)
        st.session_state.imported_crash_errors = import_errors
        if import_errors:
            st.warning("Some crash logs could not be imported: " + "; ".join(import_errors))
        elif not receipts:
            st.info("Choose one or more crash log files before importing.")
        else:
            st.success(f"Imported {len(receipts)} crash log(s) for CrashLens review. No project code was executed.")

    if run:
        target_path = Path(target).expanduser()
        if not target.strip():
            st.error("Enter a project folder before scanning.")
        elif not target_path.is_dir():
            st.error("Project folder must be an existing directory.")
        elif not modules:
            st.error("Choose at least one module.")
        else:
            with st.spinner("Scanning safely — source code is never executed or modified..."):
                requested_ignores = {item.strip() for item in extra_ignores.split(",") if item.strip()}
                ignores = _effective_ignores(target_path, requested_ignores)
                max_file_bytes = int(float(max_file_gb) * 1024**3)
                large_file_bytes = int(float(large_file_gb) * 1024**3)
                fingerprint = _scan_fingerprint(str(target_path), modules, max_file_bytes, int(max_files), large_file_bytes, ignores, req)
                st.session_state.result = analyze_project(
                    target_path,
                    max_bytes=max_file_bytes,
                    max_files=int(max_files),
                    ignores=ignores,
                    large_file_bytes=large_file_bytes,
                    enabled=set(modules),
                    requirements=req or None,
                )
                _record_language_adapter_status(st.session_state.result)
                st.session_state.scanned_target = str(target_path.resolve())
                st.session_state.requirements_raw = req
                st.session_state.scan_fingerprint = fingerprint
                st.session_state.scan_config = {
                    "modules": list(modules),
                    "max_file_size_gb": float(max_file_gb),
                    "max_files": int(max_files),
                    "large_file_threshold_gb": float(large_file_gb),
                    "additional_ignores": sorted(ignores),
                    "requirements_supplied": bool(req.strip()),
                }
                st.session_state.result.metadata["scan_id"] = hashlib.sha256(f"{fingerprint}|{st.session_state.result.started_at}".encode("utf-8")).hexdigest()[:12]

    result = st.session_state.get("result")
    pending_receipts = st.session_state.get("pending_imported_crash_receipts", [])
    pending_findings = st.session_state.get("pending_imported_crash_findings", [])
    pending_payloads = st.session_state.get("pending_imported_crash_payloads", {})
    if result and pending_receipts:
        _attach_imported_findings(result, pending_findings, pending_receipts)
        st.session_state.setdefault("crash_downloads", {}).update(pending_payloads)
        st.session_state.pending_imported_crash_receipts = []
        st.session_state.pending_imported_crash_findings = []
        st.session_state.pending_imported_crash_payloads = {}
        if st.session_state.get("imported_crash_errors"):
            result.errors.extend(st.session_state["imported_crash_errors"])
            st.session_state.imported_crash_errors = []
    if not result:
        st.subheader("Start here")
        st.write("ProjectSentinel is a deterministic release-readiness tool, not a chatbot. It finds evidence-backed issues and tells you what to verify next.")
        st.markdown("**Try it:** enter a real project folder in the sidebar and click **Scan Project**.")
        return

    scanned_target = st.session_state.get("scanned_target", str(result.root))
    current_ignores = _effective_ignores(target, {item.strip() for item in extra_ignores.split(",") if item.strip()})
    current_fingerprint = _scan_fingerprint(
        target,
        modules,
        int(float(max_file_gb) * 1024**3),
        int(max_files),
        int(float(large_file_gb) * 1024**3),
        current_ignores,
        req,
    )
    stale = bool(st.session_state.get("scan_fingerprint") and current_fingerprint != st.session_state.get("scan_fingerprint"))
    if stale:
        st.warning("The controls no longer match the displayed result. Click **Scan Project** to refresh this report; exports remain disabled until then.")
    counts = {severity.name.title(): sum(f.severity == severity for f in result.findings) for severity in Severity}
    high_priority = [f for f in result.findings if f.severity >= Severity.HIGH]
    gate = release_gate(result)
    verification_rows, verification_summary = _verification_plan_rows(result)
    adapter_rows = _adapter_status_rows(result)
    st.caption(f"Scanned target: `{scanned_target}`")
    receipt = st.container(border=True)
    with receipt:
        receipt_columns = st.columns(4)
        receipt_columns[0].metric("Scan status", "STALE" if stale else "COMPLETE")
        receipt_columns[1].metric("Scan ID", result.metadata.get("scan_id", "—"))
        receipt_columns[2].metric("Files / skipped", f"{len(result.files)} / {len(result.skipped)}")
        receipt_columns[3].metric("Duration", f"{result.duration_seconds:.2f}s")
        st.caption(f"Recorded at: {result.started_at or 'not available'} · enabled modules: {', '.join(result.module_status)}")
    st.subheader("Release snapshot")
    if result.errors:
        st.warning(f"Review required: {len(result.errors)} module or file error(s) occurred. Incomplete checks are shown below.")
    elif high_priority:
        st.warning(f"Review required: {len(high_priority)} high-priority finding(s) need attention before release.")
    else:
        st.success("No high-priority findings were produced by the enabled checks. Manual release verification is still required.")
    metrics = st.columns(5)
    for column, label in zip(metrics, ("Critical", "High", "Medium", "Low", "Info")):
        column.metric(label, counts[label])
    st.caption(f"Inspected {len(result.files)} files · skipped {len(result.skipped)} · {result.duration_seconds:.2f}s · detected: {', '.join(result.project_types)}")

    st.subheader("Release gate")
    gate_columns = st.columns(4)
    gate_columns[0].metric("Decision", gate["status"])
    gate_columns[1].metric("High/Critical", gate["confirmed_high_or_critical"])
    gate_columns[2].metric("Unverified requirements", gate["unverified_requirements"])
    gate_columns[3].metric("Verification checks", verification_summary["checks"])
    if gate["status"] == "BLOCKED":
        st.error(f"{gate['label']}: " + ("; ".join(gate["reasons"]) or "a check failed."))
    elif gate["status"] == "REVIEW":
        st.warning(f"{gate['label']}: " + ("; ".join(gate["reasons"]) or "manual review remains."))
    else:
        st.success(f"{gate['label']}. This is an automated signal, not a safety certification.")
    st.subheader("Top actions before release")
    for finding in high_priority[:5]:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path or "project"
        st.markdown(f"**{finding.severity.name.title()} · {finding.module} · {finding.title}**  ")
        st.caption(f"`{location}` · {finding.remediation or 'Review the evidence manually.'}")
    if not high_priority:
        st.caption("No high-priority actions were produced. Review medium findings and manual requirements before release.")

    tabs = st.tabs(["Summary", "Findings & evidence", "Assets", "Crash logs", "Security & privacy", "Requirements", "Verification plan", "Export report"])
    with tabs[0]:
        st.subheader("Module status")
        st.table([{"Module": name, "What it checks": MODULE_HELP[name], "Status": (f"Ran · {sum(f.module == name for f in result.findings)} findings" if result.module_status.get(name) == "completed" else result.module_status.get(name, "not run"))} for name in MODULES])
        st.subheader("Adapter status")
        if adapter_rows:
            st.table(adapter_rows)
        else:
            st.caption("No adapter status was recorded. This is not a claim that adapters are installed or healthy.")
        st.info(f"Heuristic risk signal: {result.score}/100. The release gate uses severity, confidence, module completeness, and requirement evidence; neither is a pass/fail certification or a guarantee of safety.")
        if result.skipped:
            st.write("Skipped-file reasons")
            st.dataframe(result.skipped, hide_index=True, use_container_width=True)
        if result.errors:
            st.warning("Errors: " + "; ".join(result.errors))

    with tabs[1]:
        st.write("Every finding is tied to a relative path and retained evidence. Secret values are redacted.")
        query = st.text_input("Search findings", key="finding-search")
        filters = st.columns(3)
        severities = filters[0].multiselect("Severity", ["Critical", "High", "Medium", "Low", "Info"], key="finding-severity")
        confidences = filters[1].multiselect("Confidence", ["High", "Medium", "Low"], key="finding-confidence")
        finding_modules = filters[2].multiselect("Module", MODULES, key="finding-module")
        filtered = _filtered_findings(result, query, severities, confidences, finding_modules)
        if not filtered:
            st.info("No findings match these filters. Clear a filter to inspect the full scan.")
        else:
            st.caption(f"Showing {len(filtered)} of {len(result.findings)} findings")
            st.dataframe([
                {"Priority": f.severity.name.title(), "Module": f.module, "Finding": f.title, "File": f.path or "project", "Confidence": f.confidence.name.title()}
                for f in filtered
            ], use_container_width=True, hide_index=True)
            for finding in filtered:
                location = f"{finding.path}:{finding.line}" if finding.line else finding.path or "project"
                with st.expander(f"{finding.severity.name.title()} · {finding.title} · {location}"):
                    st.write("**Why this matters**", finding.why_it_matters or "This evidence may increase release risk.")
                    st.write("**Evidence retained**")
                    st.code(finding.evidence or "No raw evidence retained")
                    st.write("**Recommended next step**", finding.remediation or "Review manually.")
                    st.caption(f"Rule: {finding.rule_id} · Confidence: {finding.confidence.name.title()}")

    with tabs[2]:
        st.write("Asset inventory and measured file properties. Heuristics do not claim runtime FPS or GPU memory.")
        st.dataframe([{"path": f.path, "bytes": f.size} for f in sorted(result.files, key=lambda item: -item.size)[:25]], hide_index=True, use_container_width=True)
        st.write("File extension distribution")
        st.bar_chart(Counter(Path(f.path).suffix.lower() or "[none]" for f in result.files))
        textures = [{"path": f.path, "width": f.metadata.get("width"), "height": f.metadata.get("height"), "bytes": f.size} for f in result.files if f.metadata.get("width")]
        if textures:
            st.write("Measured image dimensions")
            st.dataframe(textures, hide_index=True, use_container_width=True)
        duplicate_groups = [f.metadata for f in result.findings if f.rule_id == "SCENE-DUPLICATE"]
        if duplicate_groups:
            st.write("Duplicate groups — review references before deleting anything")
            st.json(duplicate_groups)

    with tabs[3]:
        st.write("CrashLens groups repeated signatures from real log/crash artifacts. A signature is evidence, not proof of root cause.")
        st.caption("Upload a .log, .trace, .crash, .ips, or named crash text file in the sidebar, then click **Import selected crash logs**. The downloadable evidence contains redacted findings and file hashes, not raw log bodies.")
        imported_logs = result.metadata.get("imported_crash_logs", [])
        if imported_logs:
            st.subheader("Imported crash logs")
            st.dataframe(imported_logs, hide_index=True, use_container_width=True)
            downloads = st.session_state.get("crash_downloads", {})
            for imported in imported_logs:
                digest = imported.get("sha256")
                payload = downloads.get(digest)
                if payload is not None:
                    name = imported.get("name", "crash.log")
                    st.download_button(
                        f"Download original {name}",
                        payload,
                        file_name=name,
                        mime="text/plain",
                        key=f"download-crash-{digest}",
                        disabled=stale,
                    )
                else:
                    st.caption(f"Original `{imported.get('name', 'crash log')}` is not retained in this session; the hash remains available for matching.")
        elif st.session_state.get("imported_crash_errors"):
            st.warning("Import issues: " + "; ".join(st.session_state["imported_crash_errors"]))
        else:
            st.caption("No external crash logs were imported for this scan. Logs found under the project folder are listed below.")
        minimum = st.number_input("Minimum occurrences", min_value=1, value=1, step=1, key="crash-min")
        crash_rows = _crash_display_rows(result, int(minimum))
        if crash_rows:
            st.dataframe(crash_rows, hide_index=True, use_container_width=True)
            st.download_button(
                "Download CrashLens evidence JSON",
                json.dumps(_crash_evidence_payload(result, int(minimum)), indent=2, sort_keys=True) + "\n",
                "projectsentinel-crash-evidence.json",
                "application/json",
                disabled=stale,
            )
        else:
            st.info("No crash-log findings matched the selected occurrence threshold.")

    with tabs[4]:
        st.write("TrustTrail is local-only. Credential-like values are redacted and no vulnerability is claimed without advisory evidence.")
        trust_rows = [f.to_dict() for f in result.findings if f.module == "TrustTrail"]
        if trust_rows:
            st.dataframe(trust_rows, hide_index=True, use_container_width=True)
        else:
            st.info("No TrustTrail findings were produced by the enabled checks.")

    with tabs[5]:
        raw_requirements = st.session_state.get("requirements_raw", "")
        verified, unverified, blocked, requirement_error = _requirements_summary(raw_requirements)
        if requirement_error:
            st.error(f"Requirements input is invalid: {requirement_error}")
        elif raw_requirements:
            cols = st.columns(3)
            cols[0].metric("Verified", verified); cols[1].metric("Unverified", unverified); cols[2].metric("Blocked", blocked)
            st.caption("ScopeGuard only accepts a completed status when real test or manual evidence supports it.")
        else:
            st.info("No requirements JSON was supplied. Add release evidence in the sidebar before scanning.")
        requirement_rows = [f.to_dict() for f in result.findings if f.module == "ScopeGuard"]
        if requirement_rows:
            st.dataframe(requirement_rows, hide_index=True, use_container_width=True)
        elif raw_requirements:
            st.info("No ScopeGuard findings were produced for the supplied requirements evidence.")

    with tabs[6]:
        st.write("Every finding produces a manual follow-up and an automated check proposal. Proposed checks are not results.")
        plan_metrics = st.columns(4)
        plan_metrics[0].metric("Findings with plans", verification_summary["findings"])
        plan_metrics[1].metric("Manual checks", verification_summary["manual_checks"])
        plan_metrics[2].metric("Automated checks", verification_summary["automated_checks"])
        plan_metrics[3].metric("Adapter commands", verification_summary["automated_available"])
        if not execution_opt_in:
            st.info("Execution controls are disabled by default. Enable **Opt-in verification execution** in the sidebar to run an adapter-provided command after selecting it.")
        else:
            st.warning("Execution is explicitly enabled for this session. Only an allowlisted adapter command can run; scanning itself remains read-only.")
        # Keep the executable selection tied to the generated plan, not to a
        # fabricated command shown in a table.
        from projectsentinel.scoring import generate_verification_plan
        generated_plan = generate_verification_plan(result)
        executable_checks = [
            (item, check)
            for item in generated_plan
            for check in item.get("checks", [])
            if check.get("kind") == "automated" and check.get("available") is True
        ]
        if executable_checks:
            labels = [f"{item['priority']} · {item['rule_id']} · {check['title']}" for item, check in executable_checks]
            selected_index = st.selectbox("Automated check to run", range(len(labels)), format_func=lambda index: labels[index])
            run_selected = st.button("Run selected automated check", disabled=not execution_opt_in or stale)
            if run_selected:
                receipt = _execute_opt_in_check(result, executable_checks[selected_index][1])
                serialised_receipt = _serialise_execution_receipt(receipt)
                st.session_state.setdefault("verification_receipts", []).append(serialised_receipt)
                result.metadata.setdefault("verification_receipts", []).append(serialised_receipt)
                if receipt.get("status") == "completed":
                    st.success("The adapter returned a completion receipt. Review it before treating the check as release evidence.")
                else:
                    st.warning(receipt.get("reason", receipt.get("error", "The adapter did not complete the check.")))
        elif execution_opt_in:
            st.caption("No adapter-provided automated command is available for these findings. Manual checks remain available below.")
        if verification_rows:
            st.dataframe(verification_rows, hide_index=True, use_container_width=True)
            for item in generated_plan:
                location = item["path"] or "project"
                if item.get("line"):
                    location += f":{item['line']}"
                with st.expander(f"{item['priority']} · {item['title']} · {location}"):
                    st.write("**Evidence retained**")
                    st.code(item.get("evidence") or "No raw evidence retained")
                    for check in item["checks"]:
                        st.write(f"**{check['kind'].title()} check — {check['status']}**")
                        st.write(check["title"])
                        st.write("\n".join(f"{index}. {step}" for index, step in enumerate(check.get("steps", []), 1)))
                        st.caption(f"Pass criteria: {check['pass_criteria']}")
        else:
            st.success("No findings produced a verification plan for this scan.")

    with tabs[7]:
        st.write("Export the evidence so a teammate or judge can review the same scan outside the app.")
        st.download_button("Download evidence JSON", json_report(result), "projectsentinel-report.json", "application/json", disabled=stale)
        st.download_button("Download reviewable HTML report", html_report(result), "projectsentinel-report.html", "text/html", disabled=stale)
        st.caption("Reports use portable relative paths, redact detected secrets, and state that this is an automated audit rather than a security certification.")


if __name__ == "__main__":
    main()
