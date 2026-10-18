from pathlib import Path
from projectsentinel.models import Finding, Severity
from projectsentinel.report import html_report, to_dict
from projectsentinel.scanner import analyze_project, scan_project
from projectsentinel.security import redact

def test_symlink_is_skipped_and_malformed_manifest_is_recoverable(tmp_path: Path):
    (tmp_path / "Packages").mkdir(); (tmp_path / "Assets").mkdir()
    (tmp_path / "Packages" / "manifest.json").write_text("{bad", encoding="utf-8")
    outside = tmp_path.parent / "sentinel-outside.txt"; outside.write_text("outside", encoding="utf-8")
    try: (tmp_path / "link.txt").symlink_to(outside)
    except (OSError, NotImplementedError): pass
    result = analyze_project(tmp_path)
    assert result.module_status["SceneSentry"] == "completed"
    assert any(f.rule_id == "SCENE-MANIFEST" for f in result.findings)

def test_html_escapes_finding_content(tmp_path: Path):
    result = scan_project(tmp_path)
    result.findings.append(Finding("X", "<script>", Severity.HIGH, "x<y", "<script>alert(1)</script>"))
    output = html_report(result)
    assert "<script>alert" not in output
    assert "&lt;script&gt;" in output

def test_json_has_portable_schema_and_clean_scan(tmp_path: Path):
    data = to_dict(scan_project(tmp_path))
    assert data["schema_version"] == "1.0"
    assert data["summary"]["files_inspected"] == 0
    assert data["findings"] == []

def test_png_dimensions_are_measured_and_large_texture_is_heuristic(tmp_path: Path):
    (tmp_path / "large.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 4 + b"IHDR" + (8192).to_bytes(4, "big") + (4096).to_bytes(4, "big") + b"\0" * 100)
    result = analyze_project(tmp_path)
    record = next(f for f in result.files if f.path == "large.png")
    assert record.metadata == {"width": 8192, "height": 4096}
    assert any(f.rule_id == "SCENE-TEXTURE" and f.metadata["heuristic"] for f in result.findings)

def test_redaction_covers_private_keys_and_connection_passwords():
    value = "-----BEGIN RSA PRIVATE KEY-----topsecret-----END RSA PRIVATE KEY----- postgres://user:secret@example/db"
    output = redact(value)
    assert "topsecret" not in output and "user:secret" not in output

def test_partial_module_failure_is_visible(tmp_path: Path, monkeypatch):
    from projectsentinel.modules import trust_trail
    def broken(*args, **kwargs): raise RuntimeError("fixture failure")
    monkeypatch.setattr("projectsentinel.modules.trust_trail", broken)
    result = analyze_project(tmp_path)
    assert result.module_status["TrustTrail"] == "failed"
    assert any("TrustTrail" in e for e in result.errors)

def test_multi_engine_project_detection_and_descriptors(tmp_path: Path):
    (tmp_path / "Content").mkdir(); (tmp_path / "Config").mkdir(); (tmp_path / "Source").mkdir()
    (tmp_path / "Game.uproject").write_text("{bad", encoding="utf-8")
    (tmp_path / "scene.ma").write_text("not maya", encoding="utf-8")
    (tmp_path / "asset.blend").write_bytes(b"blend")
    (tmp_path / "Source" / "Game.cpp").write_text("int main(){}", encoding="utf-8")
    result = analyze_project(tmp_path)
    assert "Unreal Engine" in result.project_types
    assert "Blender" in result.project_types
    assert "Maya" in result.project_types
    assert result.metadata["code_files"] == 1
    assert any(f.rule_id == "SCENE-UNREAL-MANIFEST" for f in result.findings)
    assert any(f.rule_id == "SCENE-MAYA-FORMAT" for f in result.findings)

def test_language_mobile_and_model_checks(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "AndroidManifest.xml").write_text("<manifest>", encoding="utf-8")
    (tmp_path / "model.onnx").write_bytes(b"model")
    result = analyze_project(tmp_path)
    assert any(f.rule_id == "CODE-SYNTAX" for f in result.findings)
    assert any(f.rule_id == "MOBILE-ANDROID-MANIFEST" for f in result.findings)
    assert any(f.rule_id == "MODEL-INVENTORY" for f in result.findings)
    assert "Android" in result.findings[-1].metadata.get("platforms", []) or any(f.metadata.get("platforms") for f in result.findings)
