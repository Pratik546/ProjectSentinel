from pathlib import Path
from projectsentinel.models import Finding, Severity
from projectsentinel.report import json_report, markdown_report
from projectsentinel.scanner import scan_project
from projectsentinel.scanner import analyze_project
from projectsentinel.scoring import score_findings
from projectsentinel.security import redact, safe_relative
from projectsentinel.parsers import parse_env, parse_requirements

def test_scan_is_bounded_and_ignores_generated_dirs(tmp_path: Path):
    (tmp_path / "ok.py").write_text("print('ok')", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "hidden").write_text("x", encoding="utf-8")
    result = scan_project(tmp_path)
    assert [f.path for f in result.files] == ["ok.py"]
    assert result.files[0].sha256

def test_redaction_and_deterministic_score():
    assert "SECRET" not in redact("api_key=SECRET")
    f = Finding("R", "title", Severity.HIGH, "a.py", "bad", finding_id="same")
    assert score_findings([f, f]) == 30

def test_reports_are_safe_and_stable(tmp_path: Path):
    result = scan_project(tmp_path)
    result.findings.append(Finding("R", "title", Severity.LOW, "a.py", "token=SECRET"))
    assert "SECRET" not in json_report(result)
    assert "Risk score" in markdown_report(result)

def test_safe_relative_rejects_escape(tmp_path: Path):
    try:
        safe_relative(tmp_path.parent / "outside", tmp_path)
    except ValueError:
        pass
    else:
        raise AssertionError("escape was accepted")

def test_parsers_and_builtin_analyzers(tmp_path: Path):
    assert parse_env("# comment\nTOKEN='value'\n") == {"TOKEN": "value"}
    assert parse_requirements("requests>=2\n# ignored\nrequests>=2\n") == ["requests>=2"]
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    result = analyze_project(tmp_path)
    assert result.findings[0].rule_id == "SCENE001"
    assert result.findings[0].finding_id
