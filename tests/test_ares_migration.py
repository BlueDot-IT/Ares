import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


class AresMigrationTests(unittest.TestCase):
    def test_runtime_core_lives_only_under_src_ares(self):
        self.assertTrue((SRC / "ares" / "run.py").exists())
        self.assertFalse((SRC / "tiamat").exists(), "legacy src/tiamat package should be removed")

    def test_pyproject_uses_product_distribution_and_ares_runtime_identity(self):
        content = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "bluedot-ares"', content)
        self.assertIn('ares = "ares.cli:app"', content)
        self.assertIn('include = ["ares*", "lib*"]', content)
        self.assertNotIn('name = "ares"', content)
        self.assertNotIn('tiamat =', content)
        self.assertNotIn('tiamat*', content)

    def test_source_tree_has_no_legacy_tiamat_namespace_or_env_prefixes(self):
        offenders = []
        for path in SRC.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if any(token in text for token in ("tiamat", "TIAMAT", "Tiamat")):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual([], offenders, f"legacy references remain: {offenders}")


if __name__ == "__main__":
    unittest.main()
