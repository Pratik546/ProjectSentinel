"""Optional, dependency-free structural adapters for ONNX, TFLite, and PyTorch."""
from __future__ import annotations

import io
import pickletools
import zipfile
from pathlib import Path

from ..models import Confidence, FileRecord, Finding, Severity
from ._common import make_finding, record_bytes
from .types import ModelValidationResult

MODEL_FORMATS = {".onnx": "ONNX", ".tflite": "TensorFlow Lite", ".pt": "PyTorch", ".pth": "PyTorch"}


def _varint(data: bytes, start: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    index = start
    while index < len(data) and shift <= 63:
        byte = data[index]
        index += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, index
        shift += 7
    return None


def _onnx_structure(data: bytes) -> tuple[bool, str]:
    """Parse protobuf wire framing without importing protobuf or loading a model."""
    index = 0
    fields: set[int] = set()
    count = 0
    while index < len(data):
        key = _varint(data, index)
        if key is None:
            return False, "truncated protobuf field key"
        raw_key, index = key
        field = raw_key >> 3
        wire = raw_key & 0x07
        if field <= 0:
            return False, "protobuf field number is zero"
        fields.add(field)
        count += 1
        if count > 100_000:
            return False, "protobuf field count exceeds bounded limit"
        if wire == 0:
            value = _varint(data, index)
            if value is None:
                return False, "truncated protobuf varint"
            index = value[1]
        elif wire == 1:
            index += 8
        elif wire == 2:
            length = _varint(data, index)
            if length is None:
                return False, "truncated protobuf length"
            size, index = length
            index += size
        elif wire == 5:
            index += 4
        else:
            return False, f"unsupported protobuf wire type {wire}"
        if index > len(data):
            return False, "protobuf field extends past file boundary"
    # ONNX ModelProto has ir_version=1 and graph=7/opset_import=8 in normal
    # exports.  Requiring one known field avoids calling arbitrary protobuf a
    # model, while still allowing old/minimal models to be reported as unknown.
    recognized = sorted(fields.intersection({1, 7, 8, 14}))
    if not recognized:
        return True, f"valid protobuf framing ({count} field(s)); no common ONNX ModelProto field was observed"
    return True, f"valid protobuf framing with ONNX ModelProto field(s) {recognized}"


def _tflite_structure(data: bytes) -> tuple[bool, str]:
    if len(data) < 8:
        return False, "file is shorter than a FlatBuffer root and identifier"
    root = int.from_bytes(data[:4], "little")
    if root + 8 > len(data):
        return False, "FlatBuffer root offset exceeds file boundary"
    identifier = data[root + 4:root + 8]
    if identifier != b"TFL3":
        return False, f"FlatBuffer identifier is {identifier!r}, expected b'TFL3'"
    return True, f"TFL3 FlatBuffer identifier at offset {root}"


def _pytorch_structure(data: bytes) -> tuple[bool, str]:
    if data.startswith(b"PK\x03\x04") or zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
            relevant = [name for name in names if name.endswith(("data.pkl", "version", "model.json"))]
            if relevant:
                return True, f"ZIP container with PyTorch-related entries: {', '.join(sorted(relevant)[:8])}"
            return True, f"ZIP container with {len(names)} entries; PyTorch payload was not identified"
        except (OSError, zipfile.BadZipFile):
            return False, "ZIP container could not be read safely"
    if data.startswith(b"\x80"):
        try:
            operations = list(pickletools.genops(data[:1_000_000]))
            if any(operation.name == "STOP" for operation, _, _ in operations):
                return True, f"legacy pickle framing with {len(operations)} opcode(s); pickle was disassembled, never executed"
            return False, "pickle stream has no STOP opcode within the bounded prefix"
        except (pickletools.OpcodeError, ValueError, IndexError) as exc:
            return False, f"pickle framing is malformed: {exc}"
    return False, "no recognized PyTorch ZIP or legacy pickle framing"


def validate_model(record: FileRecord) -> ModelValidationResult:
    model_format = MODEL_FORMATS.get(Path(record.path).suffix.lower())
    if not model_format:
        return ModelValidationResult(adapter="model", state="not_applicable", model_path=record.path)
    if record.size == 0:
        finding = make_finding(
            "MODEL-EMPTY",
            "Model artifact is empty",
            Severity.HIGH,
            record.path,
            "The model file has zero bytes and cannot provide structural model evidence.",
            module="SceneSentry",
            confidence=Confidence.HIGH,
            remediation="Restore or export the model artifact again and verify it with the target runtime.",
        )
        return ModelValidationResult(adapter=f"model.{model_format.lower().replace(' ', '_')}", state="malformed", findings=[finding], model_format=model_format, model_path=record.path, validation_status="empty")
    data = record_bytes(record)
    if model_format == "ONNX":
        structural, evidence = _onnx_structure(data)
    elif model_format == "TensorFlow Lite":
        structural, evidence = _tflite_structure(data)
    else:
        structural, evidence = _pytorch_structure(data)
    if structural:
        finding = make_finding(
            "MODEL-STRUCTURE",
            f"{model_format} structural evidence inspected",
            Severity.INFO,
            record.path,
            f"{model_format} artifact has recognizable container or wire-format evidence. This does not claim model validity, runtime compatibility, weights correctness, accuracy, or safety.",
            evidence=evidence,
            module="SceneSentry",
            confidence=Confidence.MEDIUM,
            actionable=False,
            metadata={"format": model_format, "validation_status": "structural_evidence", "claims": []},
        )
        return ModelValidationResult(adapter=f"model.{model_format.lower().replace(' ', '_')}", state="structural_evidence", findings=[finding], evidence={"format": model_format, "structural": evidence}, model_format=model_format, model_path=record.path, validation_status="structural_evidence", limitations=["Runtime loading, operator support, weights, accuracy, latency, and safety were not validated."])
    finding = make_finding(
        "MODEL-UNVERIFIED",
        f"{model_format} model validity is unverified",
        Severity.INFO,
        record.path,
        f"No sufficient {model_format} structural evidence was found in the bounded artifact; the adapter makes no validity claim.",
        evidence=evidence,
        module="SceneSentry",
        confidence=Confidence.HIGH,
        actionable=False,
        metadata={"format": model_format, "validation_status": "unverified", "claims": []},
    )
    return ModelValidationResult(adapter=f"model.{model_format.lower().replace(' ', '_')}", state="unsupported", findings=[finding], evidence={"format": model_format, "structural": evidence}, model_format=model_format, model_path=record.path, validation_status="unverified", limitations=["The adapter does not install or import ONNX, TensorFlow Lite, or PyTorch runtimes."])


def validate_models(files: list[FileRecord]) -> list[Finding]:
    out: list[Finding] = []
    for record in files:
        if Path(record.path).suffix.lower() in MODEL_FORMATS:
            out.extend(validate_model(record).findings)
    return out


def validate_onnx(record: FileRecord) -> ModelValidationResult:
    return validate_model(record) if Path(record.path).suffix.lower() == ".onnx" else ModelValidationResult(adapter="model.onnx", state="not_applicable", model_format="ONNX", model_path=record.path)


def validate_tflite(record: FileRecord) -> ModelValidationResult:
    return validate_model(record) if Path(record.path).suffix.lower() == ".tflite" else ModelValidationResult(adapter="model.tflite", state="not_applicable", model_format="TensorFlow Lite", model_path=record.path)


def validate_pytorch(record: FileRecord) -> ModelValidationResult:
    return validate_model(record) if Path(record.path).suffix.lower() in {".pt", ".pth"} else ModelValidationResult(adapter="model.pytorch", state="not_applicable", model_format="PyTorch", model_path=record.path)
