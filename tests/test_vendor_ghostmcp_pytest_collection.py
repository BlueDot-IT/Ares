import subprocess
import sys
import unittest
from pathlib import Path


class VendorGhostMCPPytestCollectionTests(unittest.TestCase):
    def test_vendor_ghostmcp_tests_import_package_from_repo_root(self):
        repo_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-c",
                str(repo_root / "pyproject.toml"),
                "vendor/ghostmcp/tests/test_rate_limit.py",
                "-q",
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}",
        )


if __name__ == "__main__":
    unittest.main()
