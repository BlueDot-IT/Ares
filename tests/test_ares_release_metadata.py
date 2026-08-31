import re
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import ares


EXPECTED_VERSION = "1.1.1"


class AresReleaseMetadataTests(unittest.TestCase):
    def test_release_identity_is_consistent(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        install = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        checklist = (ROOT / "docs/v1.1-release-checklist.md").read_text(encoding="utf-8")
        release_notes = ROOT / f"docs/releases/v{EXPECTED_VERSION}.md"

        self.assertEqual(project["name"], "bluedot-ares")
        self.assertEqual(project["version"], EXPECTED_VERSION)
        self.assertEqual(ares.__version__, EXPECTED_VERSION)
        self.assertIn(f"Current source version: `{EXPECTED_VERSION}`", readme)
        self.assertIn(f"gh release download v{EXPECTED_VERSION}", install)
        self.assertIn(f"bluedot_ares-{EXPECTED_VERSION}-py3-none-any.whl", install)
        self.assertIn(f"## {EXPECTED_VERSION} - ", changelog)
        self.assertIn(f"release gate for Ares {EXPECTED_VERSION}", checklist)
        self.assertTrue(release_notes.is_file())
        self.assertTrue(
            release_notes.read_text(encoding="utf-8").startswith(f"# Ares v{EXPECTED_VERSION}\n")
        )

    def test_release_workflow_uses_notes_for_the_verified_tag(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

        self.assertIn('RELEASE_NOTES="docs/releases/${GITHUB_REF_NAME}.md"', workflow)
        self.assertIn('test -f "$RELEASE_NOTES"', workflow)
        self.assertIn('--notes-file "$RELEASE_NOTES"', workflow)
        self.assertIsNone(re.search(r"--notes-file\s+docs/releases/v\d", workflow))

    def test_release_workflow_binds_tag_to_protected_main(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        _, verification_and_release = workflow.split(
            "\n  verify-tag:\n",
            maxsplit=1,
        )
        verification_job, release_and_publish = verification_and_release.split(
            "\n  release:\n",
            maxsplit=1,
        )
        release_job, _ = release_and_publish.split(
            "\n  publish-pypi:\n",
            maxsplit=1,
        )

        self.assertIn("permissions:\n      contents: read", verification_job)
        self.assertIn("fetch-depth: 0", verification_job)
        self.assertIn("persist-credentials: false", verification_job)
        self.assertIn(
            'git merge-base --is-ancestor "${GITHUB_SHA}" '
            "refs/remotes/origin/main",
            verification_job,
        )
        self.assertIn("needs: verify-tag", release_job)
        self.assertNotIn("git merge-base --is-ancestor", release_job)
        self.assertIn("persist-credentials: false", release_job)

    def test_release_workflow_pins_every_external_action(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        action_refs = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)

        self.assertTrue(action_refs)
        for action_ref in action_refs:
            self.assertRegex(action_ref, r"@(?:[0-9a-f]{40})$")

    def test_ghostmcp_release_dependency_matches_vendored_source(self):
        project = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]
        vendored_project = tomllib.loads(
            (ROOT / "vendor/ghostmcp/pyproject.toml").read_text(
                encoding="utf-8"
            )
        )["project"]

        self.assertIn(
            f"ghostmcp-server=={vendored_project['version']}",
            project["optional-dependencies"]["ghostmcp"],
        )

    def test_trusted_publisher_remains_explicitly_gated(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        _, publish_job = workflow.split("\n  publish-pypi:\n", maxsplit=1)

        self.assertIn(
            "if: github.repository == 'BlueDot-IT/Ares' && vars.PYPI_PUBLISH_ENABLED == 'true'",
            publish_job,
        )
        self.assertIn("environment:\n      name: pypi", publish_job)
        self.assertIn("permissions:\n      id-token: write", publish_job)
        self.assertIn(
            "uses: pypa/gh-action-pypi-publish@"
            "dc37677b2e1c63e2034f94d8a5b11f265b73ba33",
            publish_job,
        )
        self.assertNotIn("PYPI_API_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
