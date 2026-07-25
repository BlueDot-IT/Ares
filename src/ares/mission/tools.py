from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ares.tools.registry import ToolRegistry


# ---------------------------------------------------------
# Tool 1: redteam_secret_scan
# ---------------------------------------------------------

SECRET_PATTERNS = [
    (re.compile(r"api_key\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE), "api_key ="),
    (re.compile(r"token\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE), "token ="),
    (re.compile(r"password\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE), "password ="),
    (re.compile(r"-----BEGIN PRIVATE KEY-----"), "-----BEGIN PRIVATE KEY-----"),
    (re.compile(r"AWS_ACCESS_KEY_ID\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE), "AWS_ACCESS_KEY_ID"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "ghp_"),
]

FORBIDDEN_DIR_COMPONENTS = {".git", ".env", "node_modules", "venv", ".venv", "__pycache__"}


def is_safe_scan_path(path: Path) -> bool:
    for part in path.parts:
        if part in FORBIDDEN_DIR_COMPONENTS:
            return False
    return True


def redteam_secret_scan(
    args: dict[str, Any] | None = None,
    *,
    root: str = ".",
    paths: list[str] | None = None,
    **_context: Any,
) -> dict[str, Any]:
    if isinstance(args, dict):
        root = args.get("root", root)
        paths = args.get("paths", paths)
    if paths is None:
        paths = ["src"]
    
    findings = []
    root_path = Path(root).resolve()

    for p in paths:
        target_path = (root_path / p).resolve()
        if not target_path.exists():
            continue

        if target_path.is_file():
            _scan_file(target_path, root_path, findings)
        else:
            for dirpath, dirnames, filenames in os.walk(target_path):
                dirnames[:] = [d for d in dirnames if d not in FORBIDDEN_DIR_COMPONENTS]
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    if is_safe_scan_path(file_path):
                        _scan_file(file_path, root_path, findings)

    summary = f"Found {len(findings)} possible secret pattern." if len(findings) == 1 else f"Found {len(findings)} possible secret patterns."
    return {
        "summary": summary,
        "findings": findings,
    }


def _scan_file(file_path: Path, root_path: Path, findings: list[dict[str, Any]]) -> None:
    try:
        if file_path.stat().st_size > 1024 * 1024:
            return
        
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            if b"\x00" in chunk:
                return

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f, 1):
                for pattern, name in SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        rel_path = os.path.relpath(file_path, root_path)
                        redacted_line = line.strip()
                        if len(match.groups()) > 0:
                            val = match.group(1)
                            redacted_line = redacted_line.replace(val, "***REDACTED***")
                        else:
                            redacted_line = f"{name} = ***REDACTED***"

                        findings.append({
                            "title": "Possible hardcoded secret",
                            "severity": "medium",
                            "file": rel_path,
                            "line": idx,
                            "redacted": redacted_line,
                        })
                        break
    except Exception:
        pass


# ---------------------------------------------------------
# Tool 2: redteam_dependency_manifest_scan
# ---------------------------------------------------------

MANIFEST_MAPPING = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "poetry/pip/uv",
    "setup.py": "pip",
    "Pipfile": "pipenv",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "Gemfile": "bundler",
}


def redteam_dependency_manifest_scan(
    args: dict[str, Any] | None = None,
    *,
    root: str = ".",
    paths: list[str] | None = None,
    **_context: Any,
) -> dict[str, Any]:
    if isinstance(args, dict):
        root = args.get("root", root)
        paths = args.get("paths", paths)
    if paths is None:
        paths = ["."]
        
    found_manifests = []
    root_path = Path(root).resolve()

    for p in paths:
        target_path = (root_path / p).resolve()
        if not target_path.exists():
            continue

        if target_path.is_file():
            name = target_path.name
            if name in MANIFEST_MAPPING:
                rel = os.path.relpath(target_path, root_path)
                found_manifests.append({
                    "file": rel,
                    "type": MANIFEST_MAPPING[name],
                })
        else:
            for dirpath, dirnames, filenames in os.walk(target_path):
                dirnames[:] = [d for d in dirnames if d not in FORBIDDEN_DIR_COMPONENTS]
                for filename in filenames:
                    if filename in MANIFEST_MAPPING:
                        file_path = Path(dirpath) / filename
                        if is_safe_scan_path(file_path):
                            rel = os.path.relpath(file_path, root_path)
                            found_manifests.append({
                                "file": rel,
                                "type": MANIFEST_MAPPING[filename],
                            })

    return {
        "summary": f"Found {len(found_manifests)} dependency manifest file(s).",
        "manifests": found_manifests,
    }


# ---------------------------------------------------------
# External Tool Adapters
# ---------------------------------------------------------

def redteam_semgrep_scan(
    args: dict[str, Any] | None = None,
    *,
    target: str | None = None,
    root: str | None = None,
    **_context: Any,
) -> dict[str, Any]:
    if isinstance(args, dict):
        target = args.get("target") or args.get("root") or target
    else:
        target = target or root
    if not target:
        target = "."

    if not shutil.which("semgrep"):
        return {"status": "unavailable", "error": "semgrep is not installed"}
    try:
        res = subprocess.run(["semgrep", "scan", "--json", target], capture_output=True, text=True, timeout=60)
        return {"status": "ok", "stdout": res.stdout, "stderr": res.stderr}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def redteam_gitleaks_scan(
    args: dict[str, Any] | None = None,
    *,
    target: str | None = None,
    root: str | None = None,
    **_context: Any,
) -> dict[str, Any]:
    if isinstance(args, dict):
        target = args.get("target") or args.get("root") or target
    else:
        target = target or root
    if not target:
        target = "."

    if not shutil.which("gitleaks"):
        return {"status": "unavailable", "error": "gitleaks is not installed"}
    try:
        res = subprocess.run(["gitleaks", "detect", "--source", target, "--report-format", "json", "-q"], capture_output=True, text=True, timeout=60)
        return {"status": "ok", "stdout": res.stdout, "stderr": res.stderr}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


def redteam_osv_scan(
    args: dict[str, Any] | None = None,
    *,
    target: str | None = None,
    root: str | None = None,
    **_context: Any,
) -> dict[str, Any]:
    if isinstance(args, dict):
        target = args.get("target") or args.get("root") or target
    else:
        target = target or root
    if not target:
        target = "."

    if not shutil.which("osv-scanner"):
        return {"status": "unavailable", "error": "osv-scanner is not installed"}
    try:
        res = subprocess.run(["osv-scanner", "--json", target], capture_output=True, text=True, timeout=60)
        return {"status": "ok", "stdout": res.stdout, "stderr": res.stderr}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------
# Tool Registration
# ---------------------------------------------------------

def register_mission_tools(registry: ToolRegistry) -> None:
    if registry.get_entry("redteam_secret_scan") is None:
        registry.register(
            name="redteam_secret_scan",
            toolset="redteam_secrets",
            risk="scan",
            schema={
                "type": "object",
                "properties": {
                    "root": {"type": "string", "description": "The root path to search from."},
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "Subdirectories or files to scan."}
                }
            },
            handler=redteam_secret_scan,
            description="Scan scoped local files for obvious secret patterns with redaction.",
        )
    
    if registry.get_entry("redteam_dependency_manifest_scan") is None:
        registry.register(
            name="redteam_dependency_manifest_scan",
            toolset="redteam_deps",
            risk="scan",
            schema={
                "type": "object",
                "properties": {
                    "root": {"type": "string", "description": "The root path to search from."},
                    "paths": {"type": "array", "items": {"type": "string"}, "description": "Subdirectories or files to scan."}
                }
            },
            handler=redteam_dependency_manifest_scan,
            description="Locate dependency manifest files in scoped local paths.",
        )

    if registry.get_entry("redteam_semgrep_scan") is None:
        registry.register(
            name="redteam_semgrep_scan",
            toolset="redteam_static",
            risk="scan",
            schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target path to scan."}
                }
            },
            handler=redteam_semgrep_scan,
            description="Run semgrep on the target path.",
        )

    if registry.get_entry("redteam_gitleaks_scan") is None:
        registry.register(
            name="redteam_gitleaks_scan",
            toolset="redteam_secrets",
            risk="scan",
            schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target path to scan."}
                }
            },
            handler=redteam_gitleaks_scan,
            description="Run gitleaks on the target path.",
        )

    if registry.get_entry("redteam_osv_scan") is None:
        registry.register(
            name="redteam_osv_scan",
            toolset="redteam_deps",
            risk="scan",
            schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target path to scan."}
                }
            },
            handler=redteam_osv_scan,
            description="Run osv-scanner on the target path.",
        )
