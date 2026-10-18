"""Offline inventory and optional structural checks for ML/model artifacts."""
from pathlib import Path
from ..models import FileRecord, Finding, Severity, Confidence
from ..adapters.model import MODEL_FORMATS, validate_models
from ._util import finding

MODEL_EXTENSIONS={**MODEL_FORMATS, ".mlmodel":"Core ML", ".safetensors":"Safetensors", ".pkl":"Pickle", ".joblib":"Joblib"}

def analyze(files: list[FileRecord]) -> list[Finding]:
    models=[f for f in files if Path(f.path).suffix.lower() in MODEL_EXTENSIONS]
    if not models: return []
    out=[finding("MODEL-INVENTORY", "ML model artifacts detected", Severity.INFO, "", f"Found {len(models)} model artifact(s): " + ", ".join(sorted({MODEL_EXTENSIONS[Path(f.path).suffix.lower()] for f in models})), module="SceneSentry", confidence=Confidence.HIGH, actionable=False, metadata={"models":[{"path":f.path,"format":MODEL_EXTENSIONS[Path(f.path).suffix.lower()],"bytes":f.size} for f in models], "checks": ["inventory", "empty-file", "bounded-structural-adapters"]})]
    out.extend(validate_models(files))
    for f in models:
        if f.size == 0 and not any(item.path == f.path and item.rule_id == "MODEL-EMPTY" for item in out):
            out.append(finding("MODEL-EMPTY", "Model artifact is empty", Severity.HIGH, f.path, "The model file has zero bytes and cannot provide structural model evidence.", module="SceneSentry", confidence=Confidence.HIGH, remediation="Restore or export the model artifact again and verify it with the target runtime."))
    return out
