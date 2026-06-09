import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ContextConfigTests(unittest.TestCase):
    def test_default_config(self):
        from ares.agent.context_config import ContextConfig, load_context_config

        config = ContextConfig()
        self.assertEqual(config.mode, "compact")
        self.assertEqual(config.context_window, 32768)
        self.assertEqual(config.reserved_output_tokens, 4096)
        self.assertEqual(config.budget_tokens, 0)
        self.assertEqual(config.recent_tool_calls, 20)
        self.assertEqual(config.memory_limit, 3)
        self.assertEqual(config.raw_excerpt_chars, 6000)
        self.assertEqual(config.include_raw_excerpts, False)
        self.assertEqual(config.retrieval_limit, 6)

    def test_usable_budget_tokens_auto(self):
        from ares.agent.context_config import ContextConfig

        config = ContextConfig(context_window=32768, reserved_output_tokens=4096)
        self.assertEqual(config.usable_budget_tokens, 28672)

        config = ContextConfig(context_window=131072, reserved_output_tokens=8192)
        self.assertEqual(config.usable_budget_tokens, 122880)

    def test_usable_budget_tokens_override(self):
        from ares.agent.context_config import ContextConfig

        config = ContextConfig(context_window=32768, reserved_output_tokens=4096, budget_tokens=10000)
        self.assertEqual(config.usable_budget_tokens, 10000)

    def test_parse_env_long_mode(self):
        from ares.agent.context_config import load_context_config

        env = {
            "ARES_CONTEXT_MODE": "long",
            "ARES_CONTEXT_WINDOW": "131072",
            "ARES_RESERVED_OUTPUT_TOKENS": "8192",
            "ARES_CONTEXT_BUDGET_TOKENS": "0",
            "ARES_CONTEXT_RECENT_TOOL_CALLS": "40",
            "ARES_CONTEXT_MEMORY_LIMIT": "8",
            "ARES_CONTEXT_RETRIEVAL_LIMIT": "8",
            "ARES_CONTEXT_INCLUDE_RAW": "false",
            "ARES_CONTEXT_RAW_EXCERPT_CHARS": "6000",
        }
        config = load_context_config(env)
        self.assertEqual(config.mode, "long")
        self.assertEqual(config.context_window, 131072)
        self.assertEqual(config.reserved_output_tokens, 8192)
        self.assertEqual(config.budget_tokens, 0)
        self.assertEqual(config.recent_tool_calls, 40)
        self.assertEqual(config.memory_limit, 8)
        self.assertEqual(config.retrieval_limit, 8)
        self.assertEqual(config.include_raw_excerpts, False)
        self.assertEqual(config.raw_excerpt_chars, 6000)

    def test_invalid_env_fallbacks(self):
        from ares.agent.context_config import load_context_config

        env = {
            "ARES_CONTEXT_MODE": "invalid",
            "ARES_CONTEXT_WINDOW": "notanumber",
            "ARES_RESERVED_OUTPUT_TOKENS": "alsoinvalid",
        }
        config = load_context_config(env)
        self.assertEqual(config.mode, "compact")
        self.assertEqual(config.context_window, 32768)
        self.assertEqual(config.reserved_output_tokens, 4096)

    def test_minimum_bounds(self):
        from ares.agent.context_config import load_context_config

        env = {
            "ARES_CONTEXT_WINDOW": "100",
            "ARES_RESERVED_OUTPUT_TOKENS": "100",
        }
        config = load_context_config(env)
        self.assertEqual(config.context_window, 8192)
        self.assertEqual(config.reserved_output_tokens, 512)


if __name__ == "__main__":
    unittest.main()
