"""Offline Android and iOS manifest/permission evidence adapters."""
from __future__ import annotations

import json
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Confidence, FileRecord, Finding, Severity
from ._common import make_finding, record_bytes
from .types import AdapterResult, MobileManifestResult

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ANDROID = f"{{{ANDROID_NS}}}"

# This is an Android platform classification, not a claim about exploitability.
KNOWN_DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
}

IOS_USAGE_KEYS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSLocationWhenInUseUsageDescription": "location",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "background location",
    "NSPhotoLibraryUsageDescription": "photo library",
    "NSContactsUsageDescription": "contacts",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSUserTrackingUsageDescription": "tracking",
}


def _attr(element: ET.Element, name: str) -> str | None:
    return element.attrib.get(ANDROID + name) or element.attrib.get(name)


def _android(record: FileRecord) -> MobileManifestResult:
    permissions: list[str] = []
    findings: list[Finding] = []
    raw = record_bytes(record)
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, UnicodeDecodeError) as exc:
        findings.append(
            make_finding(
                "MOBILE-ANDROID-MANIFEST",
                "Android manifest is malformed",
                Severity.HIGH,
                record.path,
                "AndroidManifest.xml could not be parsed as XML.",
                evidence=str(exc),
                module="ScopeGuard",
                confidence=Confidence.HIGH,
                remediation="Fix the manifest XML and validate it with the Android build tools.",
            )
        )
        return MobileManifestResult(
            adapter="mobile.android",
            state="malformed",
            findings=findings,
            manifest_path=record.path,
            platform="Android",
            limitations=["Static XML parsing does not resolve Gradle manifest merging or install-time policy."],
        )

    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            name = _attr(element, "name")
            if name:
                permissions.append(name)

    for name in sorted(set(permissions)):
        classification = "known Android dangerous permission" if name in KNOWN_DANGEROUS_PERMISSIONS else "declared permission"
        findings.append(
            make_finding(
                "MOBILE-PERMISSION",
                "Android permission declared",
                Severity.INFO,
                record.path,
                f"Manifest declares {name} ({classification}); static presence is not proof of runtime use.",
                evidence=name,
                module="ScopeGuard",
                confidence=Confidence.HIGH,
                actionable=False,
                metadata={"permission": name, "classification": classification, "platform": "Android"},
            )
        )

    application = next((element for element in root.iter() if element.tag.rsplit("}", 1)[-1] == "application"), None)
    debug = _attr(application, "debuggable") if application is not None else None
    cleartext = _attr(application, "usesCleartextTraffic") if application is not None else None
    exported_missing: list[str] = []
    for element in root.iter():
        local = element.tag.rsplit("}", 1)[-1]
        if local not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        has_intent_filter = any(child.tag.rsplit("}", 1)[-1] == "intent-filter" for child in element)
        if has_intent_filter and _attr(element, "exported") is None:
            exported_missing.append(_attr(element, "name") or local)
    if exported_missing:
        findings.append(
            make_finding(
                "MOBILE-EXPORTED-MISSING",
                "Android component exported state is implicit",
                Severity.MEDIUM,
                record.path,
                "Components with intent filters do not declare android:exported; the final merged manifest and target SDK determine whether this is a build risk.",
                evidence=", ".join(exported_missing[:20]),
                module="ScopeGuard",
                confidence=Confidence.MEDIUM,
                remediation="Set android:exported explicitly for components with intent filters and validate the merged release manifest.",
                metadata={"components": exported_missing},
            )
        )
    findings.insert(
        0,
        make_finding(
            "MOBILE-MANIFEST-EVIDENCE",
            "Android manifest inspected",
            Severity.INFO,
            record.path,
            f"Parsed Android manifest XML and found {len(set(permissions))} declared permission(s). This is static manifest evidence only.",
            module="ScopeGuard",
            confidence=Confidence.HIGH,
            actionable=False,
            metadata={"platform": "Android", "permissions": sorted(set(permissions)), "debuggable": debug, "uses_cleartext_traffic": cleartext, "exported_missing": exported_missing},
        ),
    )
    return MobileManifestResult(
        adapter="mobile.android",
        state="inspected",
        findings=findings,
        evidence={"permissions": sorted(set(permissions)), "debuggable": debug, "uses_cleartext_traffic": cleartext},
        manifest_path=record.path,
        platform="Android",
        permissions=tuple(sorted(set(permissions))),
        limitations=["Manifest merging, signing, runtime permission prompts, and device behavior were not evaluated."],
    )


def _ios(record: FileRecord) -> MobileManifestResult:
    findings: list[Finding] = []
    raw = record_bytes(record)
    try:
        data = plistlib.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("property list root is not a dictionary")
    except (plistlib.InvalidFileException, ValueError, TypeError, UnicodeDecodeError) as exc:
        # Preserve the old JSON-like fixture behavior for projects that keep a
        # generated plist in JSON form.
        try:
            data = json.loads((record.text or raw.decode("utf-8")).strip())
            if not isinstance(data, dict):
                raise ValueError("JSON plist root is not an object")
        except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
            findings.append(
                make_finding(
                    "MOBILE-PLIST",
                    "Property list is malformed",
                    Severity.MEDIUM,
                    record.path,
                    "Info.plist could not be parsed as a property-list or JSON object.",
                    evidence=str(exc),
                    module="ScopeGuard",
                    confidence=Confidence.HIGH,
                    remediation="Validate Info.plist with Xcode or a property-list parser.",
                )
            )
            return MobileManifestResult(adapter="mobile.ios", state="malformed", findings=findings, platform="iOS", manifest_path=record.path)

    permissions = tuple(sorted(key for key in IOS_USAGE_KEYS if key in data))
    findings.insert(
        0,
        make_finding(
            "MOBILE-PLIST-EVIDENCE",
            "iOS property list inspected",
            Severity.INFO,
            record.path,
            f"Parsed Info.plist and found {len(permissions)} privacy usage description key(s). This is static plist evidence only.",
            module="ScopeGuard",
            confidence=Confidence.HIGH,
            actionable=False,
            metadata={"platform": "iOS", "usage_keys": list(permissions), "capabilities": [IOS_USAGE_KEYS[key] for key in permissions]},
        ),
    )
    for key in permissions:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            findings.append(
                make_finding(
                    "MOBILE-PLIST-USAGE-DESCRIPTION",
                    "iOS privacy usage description is empty",
                    Severity.MEDIUM,
                    record.path,
                    f"{key} is present but has no non-empty explanation for the user.",
                    evidence=key,
                    module="ScopeGuard",
                    confidence=Confidence.HIGH,
                    remediation="Provide a clear, localized usage description and validate the signed app's final Info.plist.",
                )
            )
    return MobileManifestResult(
        adapter="mobile.ios",
        state="inspected",
        findings=findings,
        evidence={"usage_keys": list(permissions)},
        platform="iOS",
        manifest_path=record.path,
        permissions=permissions,
        limitations=["Entitlements, code signing, privacy manifests, and runtime prompts were not evaluated."],
    )


def inspect_mobile_manifests(files: list[FileRecord]) -> list[Finding]:
    """Inspect manifests present in a scan and return only evidence findings."""
    out: list[Finding] = []
    for record in files:
        name = Path(record.path).name.lower()
        if name == "androidmanifest.xml":
            out.extend(_android(record).findings)
        elif name == "info.plist":
            out.extend(_ios(record).findings)
    return out


def inspect_mobile_file(record: FileRecord) -> AdapterResult:
    name = Path(record.path).name.lower()
    if name == "androidmanifest.xml":
        return _android(record)
    if name == "info.plist":
        return _ios(record)
    return AdapterResult(adapter="mobile", state="not_applicable")


# Explicit aliases make the optional adapter useful without requiring callers
# to know the internal manifest terminology.
analyze_mobile = inspect_mobile_manifests
analyze_mobile_permissions = inspect_mobile_manifests
