from __future__ import annotations

import tempfile
from pathlib import Path
from ares.tools.registry import ToolRegistry
from ares.mission.tools import register_mission_tools, redteam_secret_scan, redteam_dependency_manifest_scan


def test_tool_registration():
    registry = ToolRegistry()
    register_mission_tools(registry)

    entry_secrets = registry.get_entry("redteam_secret_scan")
    assert entry_secrets is not None
    assert entry_secrets.toolset == "redteam_secrets"
    assert entry_secrets.risk == "scan"

    entry_deps = registry.get_entry("redteam_dependency_manifest_scan")
    assert entry_deps is not None
    assert entry_deps.toolset == "redteam_deps"
    assert entry_deps.risk == "scan"


def test_secret_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        
        # 1. Text file with valid secret pattern
        config_file = tmp_path / "config.py"
        config_file.write_text("api_key = \"supersecret123\"\nAWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n", encoding="utf-8")

        # 2. Binary file (must be skipped)
        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03api_key = \"secret\"")

        # 3. File in forbidden directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        forbidden_file = git_dir / "secret.py"
        forbidden_file.write_text("token = \"xyz\"", encoding="utf-8")

        # Run scanner
        res = redteam_secret_scan(root=tmpdir, paths=["."])
        
        # Verify findings
        assert "Found 2 possible secret patterns" in res["summary"]
        findings = res["findings"]
        assert len(findings) == 2

        # Verify redaction
        assert findings[0]["file"] == "config.py"
        assert findings[0]["line"] == 1
        assert "supersecret123" not in findings[0]["redacted"]
        assert "api_key =" in findings[0]["redacted"]
        assert "***REDACTED***" in findings[0]["redacted"]

        assert findings[1]["file"] == "config.py"
        assert findings[1]["line"] == 2
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[1]["redacted"]
        assert "AWS_ACCESS_KEY_ID" in findings[1]["redacted"]
        assert "***REDACTED***" in findings[1]["redacted"]


def test_dep_manifest_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create manifest files
        (tmp_path / "package.json").write_text("{}", encoding="utf-8")
        (tmp_path / "requirements.txt").write_text("requests==2.28.1", encoding="utf-8")
        
        # Run dependency scanner
        res = redteam_dependency_manifest_scan(root=tmpdir, paths=["."])
        
        assert "Found 2 dependency manifest file" in res["summary"]
        manifests = res["manifests"]
        assert len(manifests) == 2
        
        files = {m["file"] for m in manifests}
        types = {m["type"] for m in manifests}
        
        assert "package.json" in files
        assert "requirements.txt" in files
        assert "npm" in types
        assert "pip" in types
