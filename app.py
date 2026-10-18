"""Streamlit UI for the offline ProjectSentinel auditor."""
from __future__ import annotations
import json, os
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

def main() -> None:
    try: import streamlit as st
    except ImportError: raise SystemExit("Install dependencies with: python -m pip install -r requirements.txt")
    from projectsentinel.scanner import analyze_project
    from projectsentinel.report import html_report, json_report
    st.set_page_config(page_title="ProjectSentinel", page_icon="🛡", layout="wide")
    st.markdown("<style>body{background:#18171d} .block-container{padding-top:2rem} [data-testid=stMetric]{background:#25222d;border:1px solid #40384f;padding:1rem;border-radius:8px}</style>", unsafe_allow_html=True)
    st.title("🛡 ProjectSentinel"); st.caption("Offline-first release-readiness auditor for Unity, Unreal, Blender, Maya, mobile apps, and software repositories")
    with st.sidebar:
        st.header("Scan configuration")
        target=st.text_input("Project directory", os.getenv("PROJECTSENTINEL_TARGET", str(ROOT)))
        max_bytes=st.number_input("Max file size (MB)", 1, 500, 20)*1024*1024
        max_files=st.number_input("Max files", 100, 100000, 25000)
        large_file_mb=st.number_input("Large-file warning threshold (MB)", 1, 2048, 25)
        extra_ignores=st.text_input("Additional excluded directory names", placeholder="GeneratedLocalRepo,temp")
        modules=st.multiselect("Modules", ["SceneSentry","CrashLens","TrustTrail","ScopeGuard"], default=["SceneSentry","CrashLens","TrustTrail","ScopeGuard"])
        req=st.text_area("Requirements JSON (optional)", placeholder='{"requirements": []}', height=100)
        run=st.button("Scan Project", type="primary", use_container_width=True)
    if run:
        if not Path(target).is_dir(): st.error("Target must be an existing directory.")
        else:
            with st.spinner("Scanning safely; no source files are modified..."):
                ignores={item.strip() for item in extra_ignores.split(",") if item.strip()}
                st.session_state.result=analyze_project(target, max_bytes=int(max_bytes), max_files=int(max_files), ignores=ignores, large_file_bytes=int(large_file_mb*1024*1024), enabled=set(modules), requirements=req or None)
    result=st.session_state.get("result")
    if not result:
        st.info("Choose a project directory and click Scan Project. Core scans run locally and do not require an API key.")
        return
    counts={s.name.title():sum(f.severity==s for f in result.findings) for s in __import__('projectsentinel.models',fromlist=['Severity']).Severity}
    cols=st.columns(5)
    for c,k in zip(cols,["Critical","High","Medium","Low","Info"]): c.metric(k,counts[k])
    st.caption(f"Inspected {len(result.files)} files · skipped {len(result.skipped)} · {result.duration_seconds:.2f}s")
    st.caption(f"Detected: {', '.join(result.project_types)} · code files: {result.metadata.get('code_files', 0)} · asset files: {result.metadata.get('asset_files', 0)}")
    tabs=st.tabs(["Overview","Findings","Assets & crashes","Security","Requirements","Reports"])
    with tabs[0]:
        st.subheader("Module status")
        st.table([{"Module":k,"Status":v} for k,v in result.module_status.items()])
        st.info(f"Risk score {result.score}/100 is a transparent heuristic based on severity and confidence; it is not a safety guarantee.")
        if result.errors: st.warning("Module errors: " + "; ".join(result.errors))
    with tabs[1]:
        q=st.text_input("Search findings"); sev=st.multiselect("Severity", ["Critical","High","Medium","Low","Info"]); conf=st.multiselect("Confidence", ["High","Medium","Low"])
        rows=[f.to_dict() for f in result.findings if (not q or q.lower() in (f.title+f.message+f.path).lower()) and (not sev or f.severity.name.title() in sev) and (not conf or f.confidence.name.title() in conf)]
        st.dataframe(rows, use_container_width=True, hide_index=True)
        for f in result.findings:
            with st.expander(f"{f.severity.name.title()} · {f.title} · {f.path or 'project'}"):
                st.write(f.message); st.code(f.evidence or "No raw evidence retained"); st.write("**Remediation:**", f.remediation or "Review manually.")
    with tabs[2]:
        st.write("Largest inspected files")
        st.dataframe([{"path":f.path,"bytes":f.size} for f in sorted(result.files,key=lambda x:-x.size)[:25]], hide_index=True, use_container_width=True)
        from collections import Counter
        st.write("File extension distribution")
        st.bar_chart(Counter((Path(f.path).suffix.lower() or "[none]") for f in result.files))
        textures=[{"path":f.path,"width":f.metadata.get("width"),"height":f.metadata.get("height"),"bytes":f.size} for f in result.files if f.metadata.get("width")]
        if textures: st.write("Measured image dimensions"); st.dataframe(textures, hide_index=True, use_container_width=True)
        duplicates=[f.metadata for f in result.findings if f.rule_id == "SCENE-DUPLICATE"]
        if duplicates: st.write("Duplicate groups"); st.json(duplicates)
        st.write("CrashLens error groups")
        min_occurrences=st.number_input("Minimum occurrences", min_value=1, value=1, step=1, key="crash-min")
        crash_rows=[f.to_dict() for f in result.findings if f.rule_id == "CRASH-ERROR" and f.metadata.get("occurrences", 0) >= min_occurrences]
        st.dataframe(crash_rows, hide_index=True, use_container_width=True)
    with tabs[3]: st.write("TrustTrail findings are redacted and local-only."); st.dataframe([f.to_dict() for f in result.findings if f.module.lower()=="trusttrail"], hide_index=True, use_container_width=True)
    with tabs[4]: st.write("ScopeGuard never marks a requirement complete from keywords alone. Attach real test or manual evidence in your JSON.")
    with tabs[5]:
        st.download_button("Download JSON", json_report(result), "projectsentinel-report.json", "application/json")
        st.download_button("Download HTML", html_report(result), "projectsentinel-report.html", "text/html")

if __name__ == "__main__": main()
