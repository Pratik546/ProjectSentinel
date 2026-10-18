"""Conservative, offline checks that work across common programming languages.

This is deliberately a syntax/evidence auditor, not a replacement for each
language's compiler, type checker, or test runner.
"""
import ast, json, re
from pathlib import Path
from ..models import FileRecord, Finding, Severity, Confidence
from ._util import finding

LANGUAGE_EXTENSIONS = {
    ".py": "Python", ".pyw": "Python", ".cs": "C#", ".c": "C", ".h": "C/C++",
    ".cc": "C++", ".cpp": "C++", ".hpp": "C++", ".java": "Java", ".kt": "Kotlin",
    ".kts": "Kotlin", ".js": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript",
    ".tsx": "TypeScript", ".go": "Go", ".rs": "Rust", ".swift": "Swift",
    ".dart": "Dart", ".lua": "Lua", ".rb": "Ruby", ".php": "PHP", ".m": "Objective-C",
    ".mm": "Objective-C++", ".scala": "Scala", ".sh": "Shell", ".bash": "Shell",
    ".ps1": "PowerShell", ".mel": "MEL", ".shader": "Shader", ".hlsl": "HLSL",
}

def _balanced(text: str) -> bool:
    pairs = {"}": "{", "]": "[", ")": "("}; stack=[]; quote=None; escaped=False
    for ch in text:
        if quote:
            if escaped: escaped=False
            elif ch == "\\": escaped=True
            elif ch == quote: quote=None
        elif ch in "'\"`": quote=ch
        elif ch in "{[": stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]: return False
    return not stack and quote is None

def analyze(files: list[FileRecord]) -> list[Finding]:
    out=[]
    for f in files:
        if not f.text: continue
        suffix=Path(f.path).suffix.lower(); language=LANGUAGE_EXTENSIONS.get(suffix)
        if not language: continue
        if "<<<<<<< " in f.text or "=======\n" in f.text or ">>>>>>> " in f.text:
            out.append(finding("CODE-MERGE-CONFLICT", "Unresolved merge conflict marker", Severity.HIGH, f.path, f"A merge-conflict marker was found in {language} source.", module="SceneSentry", confidence=Confidence.HIGH, remediation="Resolve the conflict and run the language's normal build or test command."))
        if language == "Python":
            try: ast.parse(f.text, filename=f.path)
            except SyntaxError as exc:
                out.append(finding("CODE-SYNTAX", "Python syntax error", Severity.HIGH, f.path, "Python source could not be parsed; this is a syntax finding, not a runtime proof.", exc.lineno, exc.msg, module="SceneSentry", confidence=Confidence.HIGH, remediation="Fix the reported syntax error and run the project's Python test suite."))
    return out
