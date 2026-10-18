"""Fixture-backed checks for optional, read-only ProjectSentinel adapters."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from projectsentinel.adapters.assets import validate_assets
from projectsentinel.adapters.build import validate_build_evidence
from projectsentinel.adapters.crash import import_crash_logs
from projectsentinel.adapters.dependencies import analyze_dependencies
from projectsentinel.adapters.mobile import inspect_mobile_manifests
from projectsentinel.adapters.model import validate_model
from projectsentinel.models import FileRecord
from projectsentinel.security import sha256_bytes


def record(path: str, data: bytes | str) -> FileRecord:
    raw = data.encode() if isinstance(data, str) else data
    text = data if isinstance(data, str) else None
    return FileRecord(path, len(raw), sha256_bytes(raw), text, {}, raw if text is None else None)


def test_android_permissions_and_exported_state_are_evidence_based():
    manifest = """<manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.CAMERA" />
      <application android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity"><intent-filter /></activity>
      </application>
    </manifest>"""
    findings = inspect_mobile_manifests([record("app/src/main/AndroidManifest.xml", manifest)])
    rules = {item.rule_id for item in findings}
    assert "MOBILE-MANIFEST-EVIDENCE" in rules
    assert "MOBILE-PERMISSION" in rules
    assert "MOBILE-EXPORTED-MISSING" in rules


def test_build_adapter_reports_log_evidence_without_running_a_build():
    files = [
        record("Packages/manifest.json", "{}"),
        record("Editor.log", "Build completed with a result of 'Succeeded'.\n"),
    ]
    result = validate_build_evidence(files)
    assert result.engine == "Unity"
    assert result.passed is True
    assert any(item.rule_id == "BUILD-SUCCESS-EVIDENCE" for item in result.findings)
    assert all(item.metadata.get("claims", []) == [] for item in result.findings if item.rule_id == "BUILD-SUCCESS-EVIDENCE")


def test_local_advisory_database_only_matches_exact_evidence():
    files = [record("requirements.txt", "requests==2.0\n")]
    database = {"vulnerabilities": [{"id": "CVE-LOCAL-1", "package": {"name": "requests", "ecosystem": "PyPI"}, "versions": ["2.0"], "summary": "fixture advisory"}]}
    result = analyze_dependencies(files, database)
    matches = [item for item in result.findings if item.rule_id == "TRUST-VULNERABILITY"]
    assert len(matches) == 1
    assert matches[0].metadata["evidence_basis"] == "exact local advisory match"

    no_database = analyze_dependencies(files)
    assert not any(item.rule_id == "TRUST-VULNERABILITY" for item in no_database.findings)
    assert any(item.rule_id == "TRUST-AUDIT-LIMIT" for item in no_database.findings)

    osv = {"vulnerabilities": [{"id": "CVE-OSV-1", "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "versions": ["2.0"]}]}]}
    assert any(item.rule_id == "TRUST-VULNERABILITY" for item in analyze_dependencies(files, osv).findings)


def test_crash_import_accepts_a_local_file_without_executing_it(tmp_path: Path):
    path = tmp_path / "logcat.txt"
    path.write_text("FATAL EXCEPTION: main\nFATAL EXCEPTION: main\n", encoding="utf-8")
    result = import_crash_logs(path)
    assert result.logs[0].format == "android-logcat"
    assert result.logs[0].occurrences == 2
    assert result.findings[0].metadata["root_cause_claim"] is False
    assert import_crash_logs([path]).logs[0].occurrences == 2


def test_engine_asset_headers_and_model_adapters_are_structural_only():
    assets = validate_assets([
        record("Content/Props/thing.uasset", (0x9E2A83C1).to_bytes(4, "little") + b"payload"),
    ])
    assert any(item.rule_id == "ASSET-UNREAL-HEADER" for item in assets.findings)
    assert assets.findings[0].metadata["claims"] == []

    onnx = validate_model(record("model.onnx", b"\x08\x01"))
    assert onnx.validation_status == "structural_evidence"
    assert onnx.findings[0].metadata["claims"] == []

    tflite = validate_model(record("model.tflite", b"\x04\x00\x00\x00\x00\x00\x00\x00TFL3"))
    assert tflite.validation_status == "structural_evidence"

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("model/data.pkl", b"not loaded")
        archive.writestr("model/version", b"3")
    pytorch = validate_model(record("model.pt", output.getvalue()))
    assert pytorch.validation_status == "structural_evidence"
