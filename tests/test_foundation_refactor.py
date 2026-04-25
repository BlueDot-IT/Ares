import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class FoundationPackageTests(unittest.TestCase):
    def test_package_exposes_version(self):
        import ares

        self.assertIsInstance(ares.__version__, str)
        self.assertGreater(len(ares.__version__), 0)


class ConfigLoaderTests(unittest.TestCase):
    def test_load_config_uses_default_home_and_env_overrides(self):
        from ares.config.loader import load_config

        with tempfile.TemporaryDirectory() as tmp:
            old_home = os.environ.get("ARES_HOME")
            old_model = os.environ.get("ARES_LLM_MODEL")
            try:
                os.environ["ARES_HOME"] = tmp
                os.environ["ARES_LLM_MODEL"] = "unit-test-model"

                cfg = load_config()

                self.assertEqual(cfg.home, Path(tmp))
                self.assertEqual(cfg.llm.model, "unit-test-model")
                self.assertEqual(cfg.policy.default_mode, "safe-active")
                self.assertTrue(cfg.policy.allow_private_only)
            finally:
                if old_home is None:
                    os.environ.pop("ARES_HOME", None)
                else:
                    os.environ["ARES_HOME"] = old_home
                if old_model is None:
                    os.environ.pop("ARES_LLM_MODEL", None)
                else:
                    os.environ["ARES_LLM_MODEL"] = old_model


class ToolRegistryTests(unittest.TestCase):
    def test_registry_filters_unavailable_tools_and_dispatches_available_tool(self):
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={
                "name": "echo_tool",
                "description": "Echo text",
                "parameters": {
                    "type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"],
                },
            },
            handler=lambda args, **_: {"echo": args["text"]},
            check_fn=lambda: True,
            requires=["python"],
        )
        registry.register(
            name="missing_tool",
            toolset="unit",
            risk="active",
            schema={"name": "missing_tool", "description": "Unavailable", "parameters": {"type": "object"}},
            handler=lambda args, **_: args,
            check_fn=lambda: False,
            requires=["missing-binary"],
        )

        definitions = registry.get_tool_definitions(enabled_toolsets={"unit"})
        self.assertEqual([tool["function"]["name"] for tool in definitions], ["echo_tool"])

        result = registry.dispatch("echo_tool", {"text": "hello"})
        self.assertEqual(result, {"echo": "hello"})

        availability = registry.check_tool_availability()
        self.assertTrue(availability["echo_tool"].available)
        self.assertFalse(availability["missing_tool"].available)

    def test_registry_enforces_risk_ceiling(self):
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        for name, risk in [("passive_tool", "passive"), ("intrusive_tool", "intrusive")]:
            registry.register(
                name=name,
                toolset="unit",
                risk=risk,
                schema={"name": name, "description": name, "parameters": {"type": "object"}},
                handler=lambda args, **_: args,
                check_fn=lambda: True,
            )

        definitions = registry.get_tool_definitions(enabled_toolsets={"unit"}, max_risk="active")
        self.assertEqual([tool["function"]["name"] for tool in definitions], ["passive_tool"])


if __name__ == "__main__":
    unittest.main()
