from pathlib import Path
from types import SimpleNamespace

from app import _adapter_status_rows, _crash_display_rows, _crash_evidence_payload, _default_target, _effective_ignores, _execute_opt_in_check, _parse_imported_crash_logs, _uploaded_crash_payloads, _verification_plan_rows
from projectsentinel.models import FileRecord, Finding, ScanResult, Severity
from projectsentinel.adapters.crash import import_crash_logs
from projectsentinel.report import html_report, to_dict
from projectsentinel.scoring import generate_verification_plan, verification_plan_summary


def test_verification_plan_has_concrete_manual_and_automated_checks(tmp_path: Path):
    result = ScanResult(tmp_path, findings=[
        Finding(
            "CRASH-ERROR",
            "Repeated log error",
            Severity.HIGH,
            "imported/crash.log",
            "Observed an exception",
            evidence="exception token=SECRET",
        )
    ])

    plan = generate_verification_plan(result)

    assert len(plan) == 1
    assert {check["kind"] for check in plan[0]["checks"]} == {"manual", "automated"}
    assert plan[0]["manual"]["steps"]
    assert plan[0]["automated"]["steps"]
    assert plan[0]["automated"]["status"] == "not_run"
    assert verification_plan_summary(plan) == {
        "findings": 1,
        "checks": 2,
        "manual_checks": 1,
        "automated_checks": 1,
        "automated_available": 0,
    }


def test_report_schema_contains_plan_adapters_and_import_receipts(tmp_path: Path):
    result = ScanResult(
        tmp_path,
        findings=[Finding("TRUST-SECRET", "Possible secret", Severity.HIGH, "config.py", "token=SECRET")],
        metadata={
            "adapter_status": {"python": {"status": "inspected", "version": "3.12"}},
            "imported_crash_logs": [{"name": "crash.log", "bytes": 24, "sha256": "abc"}],
        },
    )

    data = to_dict(result)

    assert data["schema_version"] == "1.1"
    assert data["verification_plan"][0]["manual"]["kind"] == "manual"
    assert data["verification_plan"][0]["automated"]["kind"] == "automated"
    assert data["adapters"][0]["status"] == "inspected"
    assert data["imported_crash_logs"][0]["name"] == "crash.log"
    assert "token=SECRET" not in str(data)
    output = html_report(result)
    assert "Verification plan" in output
    assert "Adapter status" in output
    assert "Imported crash logs" in output
    assert "token=SECRET" not in output


def test_ui_facing_helpers_preserve_adapter_and_imported_log_evidence(tmp_path: Path):
    result = ScanResult(
        tmp_path,
        findings=[Finding("CODE-SYNTAX", "Syntax error", Severity.HIGH, "main.py", "bad")],
        metadata={"adapter_status": [{"name": "python", "status": "inspected"}]},
    )
    rows, summary = _verification_plan_rows(result)

    assert len(rows) == 2
    assert summary["manual_checks"] == 1
    assert _adapter_status_rows(result)[0]["Adapter"] == "python"


def test_adapter_command_is_available_only_when_recorded(tmp_path: Path):
    result = ScanResult(
        tmp_path,
        findings=[Finding("CODE-MERGE-CONFLICT", "Conflict", Severity.HIGH, "src/main.cs", "marker")],
        metadata={
            "adapter_commands": [{
                "name": "C#",
                "status": "proposed",
                "command": ["dotnet", "build", "app.csproj", "--no-restore"],
                "evidence": ["app.csproj"],
            }],
        },
    )

    plan = generate_verification_plan(result)

    automated = plan[0]["automated"]
    assert automated["available"] is True
    assert automated["command"] == ["dotnet", "build", "app.csproj", "--no-restore"]
    assert _execute_opt_in_check(result, {"available": False})["status"] == "not_available"


def test_non_ui_report_discovers_real_language_adapter_status(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "main.js").write_text("<<<<<<< ours\nconst value = 1;\n=======\nconst value = 2;\n>>>>>>> theirs\n", encoding="utf-8")

    from projectsentinel.scanner import analyze_project

    data = to_dict(analyze_project(tmp_path))

    javascript = [item for item in data["adapter_status"] if item.get("name") == "JavaScript"]
    assert javascript
    assert javascript[0]["status"] in {"proposed", "skipped"}
    assert data["summary"]["adapter_count"] >= 1
    assert data["verification_plan"]
    automated = next(item["automated"] for item in data["verification_plan"] if item["rule_id"] == "CODE-MERGE-CONFLICT")
    if javascript[0]["status"] == "proposed":
        assert automated["available"] is True
        assert automated["command"]


def test_imported_crash_log_parser_is_bounded_and_read_only():
    upload = SimpleNamespace(name="..\\mobile.crash", getvalue=lambda: b"Fatal exception\nFatal exception\n")

    receipts, findings, errors = _parse_imported_crash_logs([upload])

    assert errors == []
    assert receipts[0]["path"] == "imported/mobile.crash"
    assert receipts[0]["bytes"] == len(upload.getvalue())
    assert findings[0].path == "imported/mobile.crash"


def test_empty_target_configuration_defaults_to_the_workspace(monkeypatch):
    monkeypatch.delenv("PROJECTSENTINEL_TARGET", raising=False)
    assert Path(_default_target()).is_dir()


def test_explicit_target_configuration_is_preserved(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("PROJECTSENTINEL_TARGET", str(tmp_path))
    assert _default_target() == str(tmp_path)


def test_workspace_scan_excludes_generated_app_data_but_preserves_user_ignores():
    ignores = _effective_ignores(Path.cwd(), {"custom-generated"})
    assert "custom-generated" in ignores
    assert {".opencode", ".omnirush", "reports"}.issubset(ignores)


def test_crash_adapter_does_not_treat_docs_as_crash_logs():
    record = FileRecord("README.md", 44, "digest", "The error handling guidance is documented here.")

    result = import_crash_logs([record])

    assert result.logs == ()
    assert result.findings == []


def test_crash_ui_rows_and_download_payload_are_compact_and_redacted(tmp_path: Path):
    result = ScanResult(
        tmp_path,
        findings=[Finding(
            "CRASH-ERROR",
            "Repeated log error",
            Severity.HIGH,
            "logs/mobile.log",
            "Observed an exception",
            line=8,
            evidence="exception token=SECRET",
            metadata={"occurrences": 2, "log_format": "android-logcat", "signature": "FATAL exception <value>"},
        )],
        metadata={"imported_crash_logs": [{"name": "mobile.log", "bytes": 32, "sha256": "hash"}]},
    )

    rows = _crash_display_rows(result, 1)
    payload = _crash_evidence_payload(result, 1)

    assert rows == [{
        "Severity": "High",
        "Log path": "logs/mobile.log",
        "Line": 8,
        "Occurrences": 2,
        "Format": "android-logcat",
        "Signature": "FATAL exception <value>",
    }]
    assert payload["findings"][0]["path"] == "logs/mobile.log"
    assert "token=SECRET" not in str(payload)
    assert payload["imported_crash_logs"][0]["sha256"] == "hash"


def test_imported_crash_bytes_are_available_for_explicit_original_download():
    payload = b"FATAL EXCEPTION: main\n"
    upload = SimpleNamespace(name="device.log", getvalue=lambda: payload)

    downloads = _uploaded_crash_payloads([upload])

    from projectsentinel.security import sha256_bytes
    assert downloads == {sha256_bytes(payload): payload}
