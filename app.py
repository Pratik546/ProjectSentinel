"""Judge-friendly Streamlit UI for the offline ProjectSentinel auditor."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import os
import sys

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


def main() -> None:
    try:
        import streamlit as st
    except ImportError as exc:
        raise SystemExit("Install dependencies with: python -m pip install -r requirements-lock.txt") from exc

    from projectsentinel.models import Severity
    from projectsentinel.report import html_report, json_report
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

    demo_target = ROOT / "examples" / "sample_unity_project"
    default_target = os.getenv("PROJECTSENTINEL_TARGET", str(demo_target if demo_target.is_dir() else ROOT))

    st.markdown(
        """<div class="hero"><h1>🛡 ProjectSentinel</h1>
        <p><b>Find what to fix before release.</b> Scan a project locally, inspect file-level evidence, and export a reviewable report.</p>
        <p class="step">1 Choose a project&nbsp;&nbsp; → &nbsp;&nbsp;2 Scan locally&nbsp;&nbsp; → &nbsp;&nbsp;3 Review evidence and export</p>
        </div>""", unsafe_allow_html=True,
    )
    st.info("60-second demo: scan the preloaded sample, open **Findings & evidence**, then download the HTML report. Project files are read-only and never uploaded.")

    with st.sidebar:
        st.header("1 · Choose a project")
        target = st.text_input("Project folder (read-only)", default_target, help="Use the project root when possible. For Unity, choose the folder containing Assets, Packages, and ProjectSettings.")
        if st.button("Use sample project", use_container_width=True):
            st.session_state.target_input = str(demo_target)
            st.rerun()
        st.caption("For the demo: examples/sample_unity_project")

        st.header("2 · Choose checks")
        modules = st.multiselect(
            "Modules to run",
            MODULES,
            default=MODULES,
            format_func=lambda name: f"{name} — {MODULE_HELP[name]}",
        )
        with st.expander("Advanced scan limits", expanded=False):
            max_bytes = st.number_input("Max file size (MB)", 1, 500, 20)
            max_files = st.number_input("Max files", 100, 100000, 25000)
            large_file_mb = st.number_input("Large-file threshold (MB)", 1, 2048, 25)
            extra_ignores = st.text_input("Additional folders to skip", placeholder="GeneratedLocalRepo,temp")
        req = st.text_area("Release requirements evidence (optional)", placeholder='{"requirements": []}', height=100)
        run = st.button("Scan Project", type="primary", use_container_width=True)
        st.caption("Privacy: local-only, read-only, no API key required.")

    if "target_input" in st.session_state:
        target = st.session_state.target_input
    if run:
        target_path = Path(target).expanduser()
        if not target_path.is_dir():
            st.error("Project folder must be an existing directory.")
        elif not modules:
            st.error("Choose at least one module.")
        else:
            with st.spinner("Scanning safely — source code is never executed or modified..."):
                ignores = {item.strip() for item in extra_ignores.split(",") if item.strip()}
                st.session_state.result = analyze_project(
                    target_path,
                    max_bytes=int(max_bytes) * 1024 * 1024,
                    max_files=int(max_files),
                    ignores=ignores,
                    large_file_bytes=int(large_file_mb) * 1024 * 1024,
                    enabled=set(modules),
                    requirements=req or None,
                )
                st.session_state.scanned_target = str(target_path.resolve())
                st.session_state.requirements_raw = req

    result = st.session_state.get("result")
    if not result:
        st.subheader("Start here")
        st.write("ProjectSentinel is a deterministic release-readiness tool, not a chatbot. It finds evidence-backed issues and tells you what to verify next.")
        st.markdown("**Try the demo:** choose the sample project in the sidebar and click **Scan Project**.")
        return

    scanned_target = st.session_state.get("scanned_target", str(result.root))
    counts = {severity.name.title(): sum(f.severity == severity for f in result.findings) for severity in Severity}
    high_priority = [f for f in result.findings if f.severity >= Severity.HIGH]
    st.caption(f"Scanned target: `{scanned_target}`")
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

    st.subheader("Top actions before release")
    for finding in high_priority[:5]:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path or "project"
        st.markdown(f"**{finding.severity.name.title()} · {finding.module} · {finding.title}**  ")
        st.caption(f"`{location}` · {finding.remediation or 'Review the evidence manually.'}")
    if not high_priority:
        st.caption("No high-priority actions were produced. Review medium findings and manual requirements before release.")

    tabs = st.tabs(["Summary", "Findings & evidence", "Assets", "Crash logs", "Security & privacy", "Requirements", "Export report"])
    with tabs[0]:
        st.subheader("Module status")
        st.table([{"Module": name, "What it checks": MODULE_HELP[name], "Status": result.module_status.get(name, "not run")} for name in MODULES])
        st.info(f"Heuristic risk signal: {result.score}/100. This prioritizes severity and confidence; it is not a pass/fail certification or a guarantee of safety.")
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
        st.write("CrashLens groups repeated log signatures. A log message is evidence, not proof of root cause.")
        minimum = st.number_input("Minimum occurrences", min_value=1, value=1, step=1, key="crash-min")
        crash_rows = [f.to_dict() for f in result.findings if f.rule_id == "CRASH-ERROR" and f.metadata.get("occurrences", 0) >= minimum]
        st.dataframe(crash_rows, hide_index=True, use_container_width=True)

    with tabs[4]:
        st.write("TrustTrail is local-only. Credential-like values are redacted and no vulnerability is claimed without advisory evidence.")
        st.dataframe([f.to_dict() for f in result.findings if f.module == "TrustTrail"], hide_index=True, use_container_width=True)

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
        st.dataframe([f.to_dict() for f in result.findings if f.module == "ScopeGuard"], hide_index=True, use_container_width=True)

    with tabs[6]:
        st.write("Export the evidence so a teammate or judge can review the same scan outside the app.")
        st.download_button("Download evidence JSON", json_report(result), "projectsentinel-report.json", "application/json")
        st.download_button("Download reviewable HTML report", html_report(result), "projectsentinel-report.html", "text/html")
        st.caption("Reports use portable relative paths, redact detected secrets, and state that this is an automated audit rather than a security certification.")


if __name__ == "__main__":
    main()
