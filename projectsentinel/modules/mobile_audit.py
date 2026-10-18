"""Static mobile-project checks for Android, iOS, Flutter, and React Native."""
import json, re, xml.etree.ElementTree as ET
from pathlib import Path
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding

def analyze(files: list[FileRecord]) -> list[Finding]:
    out=[]; paths={f.path for f in files}; names={Path(p).name.lower() for p in paths}
    android = any(p.lower().endswith("androidmanifest.xml") for p in paths) or "gradlew" in names or any(p.lower().endswith((".gradle", ".gradle.kts")) for p in paths)
    ios = "info.plist" in names or "podfile" in names or any(p.lower().endswith((".xcodeproj", ".xcworkspace")) for p in paths)
    flutter = "pubspec.yaml" in names
    react_native = any(Path(p).name == "package.json" for p in paths) and any("react-native" in (f.text or "").lower() for f in files if Path(f.path).name == "package.json")
    detected=[name for name, ok in (("Android", android),("iOS", ios),("Flutter", flutter),("React Native", react_native)) if ok]
    if not detected: return out
    out.append(finding("MOBILE-PROJECT-TYPE", "Mobile project detected", Severity.INFO, "", "Detected mobile platform(s): " + ", ".join(detected), module="ScopeGuard", confidence=Confidence.HIGH, actionable=False, metadata={"platforms": detected}))
    for f in files:
        lower=Path(f.path).name.lower()
        if lower == "androidmanifest.xml" and f.text:
            try: ET.fromstring(f.text)
            except ET.ParseError as exc:
                out.append(finding("MOBILE-ANDROID-MANIFEST", "Android manifest is malformed", Severity.HIGH, f.path, "AndroidManifest.xml could not be parsed as XML.", evidence=str(exc), module="ScopeGuard", confidence=Confidence.HIGH, remediation="Fix the manifest XML and validate it with the Android build tools."))
        if lower == "info.plist" and f.text and f.text.lstrip().startswith("{"):
            try: json.loads(f.text)
            except json.JSONDecodeError as exc:
                out.append(finding("MOBILE-PLIST", "Property list appears malformed", Severity.MEDIUM, f.path, "The plist uses JSON-like content but could not be parsed.", evidence=str(exc), module="ScopeGuard", confidence=Confidence.MEDIUM, remediation="Validate Info.plist with Xcode or a plist parser."))
        if f.text and re.search(r"(?i)debuggable\s*[=:]\s*true|android:usesCleartextTraffic\s*=\s*['\"]true", f.text):
            out.append(finding("MOBILE-DEBUG-CONFIG", "Mobile debug or cleartext setting is enabled", Severity.MEDIUM, f.path, "A development-oriented mobile configuration was found; release intent was not established.", module="TrustTrail", confidence=Confidence.MEDIUM, remediation="Confirm this is intentional and disable debug/cleartext behavior in production builds."))
    return out
