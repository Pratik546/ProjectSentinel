"""Offline inventory checks for common ML/model artifacts."""
from pathlib import Path
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding

MODEL_EXTENSIONS={".onnx":"ONNX", ".tflite":"TensorFlow Lite", ".mlmodel":"Core ML", ".pt":"PyTorch", ".pth":"PyTorch", ".safetensors":"Safetensors", ".pkl":"Pickle", ".joblib":"Joblib"}

def analyze(files: list[FileRecord]) -> list[Finding]:
    models=[f for f in files if Path(f.path).suffix.lower() in MODEL_EXTENSIONS]
    if not models: return []
    out=[finding("MODEL-INVENTORY", "ML model artifacts detected", Severity.INFO, "", f"Found {len(models)} model artifact(s): " + ", ".join(sorted({MODEL_EXTENSIONS[Path(f.path).suffix.lower()] for f in models})), module="SceneSentry", confidence=Confidence.HIGH, actionable=False, metadata={"models":[{"path":f.path,"format":MODEL_EXTENSIONS[Path(f.path).suffix.lower()],"bytes":f.size} for f in models], "checks": ["inventory", "empty-file"]})]
    for f in models:
        if f.size == 0:
            out.append(finding("MODEL-EMPTY", "Model artifact is empty", Severity.HIGH, f.path, "The model file has zero bytes and cannot be loaded as a model artifact.", module="SceneSentry", confidence=Confidence.HIGH, remediation="Restore or export the model artifact again and verify it with the target runtime."))
    return out
