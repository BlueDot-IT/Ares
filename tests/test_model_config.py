import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class ModelConfigTests(unittest.TestCase):
    def test_load_config_uses_persisted_model_settings_and_env_overrides(self):
        from ares.config.loader import load_config, save_llm_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                save_llm_config(home=Path(tmp), provider="openai", model="persisted-model", openai_base_url="http://127.0.0.1:11434/v1")
                cfg = load_config()
                self.assertEqual(cfg.llm.provider, "openai")
                self.assertEqual(cfg.llm.model, "persisted-model")
                self.assertEqual(cfg.llm.openai_base_url, "http://127.0.0.1:11434/v1")

                os.environ["ARES_LLM_MODEL"] = "env-model"
                cfg = load_config()
                self.assertEqual(cfg.llm.model, "env-model")
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_load_config_uses_provider_specific_default_base_url_for_openrouter(self):
        from ares.config.loader import load_config, save_llm_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                save_llm_config(home=Path(tmp), provider="openrouter", model="openrouter/auto")
                cfg = load_config()

                self.assertEqual(cfg.llm.provider, "openrouter")
                self.assertEqual(cfg.llm.openai_base_url, "https://openrouter.ai/api/v1")
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_load_config_uses_blank_openai_base_url_for_native_providers(self):
        from ares.config.loader import load_config, save_llm_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                save_llm_config(home=Path(tmp), provider="anthropic", model="claude-3-7-sonnet")
                cfg = load_config()

                self.assertEqual(cfg.llm.provider, "anthropic")
                self.assertEqual(cfg.llm.openai_base_url, "")
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_named_model_profiles_and_ui_theme_persist_in_config(self):
        from ares.config.loader import apply_llm_profile, load_config, save_ui_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                apply_llm_profile(home=Path(tmp), profile="openrouter")
                save_ui_config(home=Path(tmp), theme="matrix")
                cfg = load_config()

                self.assertEqual(cfg.llm.provider, "openrouter")
                self.assertEqual(cfg.llm.openai_base_url, "https://openrouter.ai/api/v1")
                self.assertEqual(cfg.ui.theme, "matrix")
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_load_config_persists_fallback_model_chain(self):
        from ares.config.loader import load_config, save_llm_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                save_llm_config(
                    home=Path(tmp),
                    provider="openai",
                    model="primary-model",
                    fallbacks=["openrouter/backup-alpha", "anthropic/claude-3-7-sonnet"],
                )
                cfg = load_config()

                self.assertEqual(cfg.llm.provider, "openai")
                self.assertEqual(cfg.llm.model, "primary-model")
                self.assertEqual(cfg.llm.fallbacks, ("openrouter/backup-alpha", "anthropic/claude-3-7-sonnet"))
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_save_llm_config_normalizes_duplicate_fallback_references(self):
        from ares.config.loader import load_config, save_llm_config

        keys = ["ARES_HOME", "ARES_LLM_PROVIDER", "ARES_LLM_MODEL", "ARES_OPENAI_BASE_URL"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                for key in keys[1:]:
                    os.environ.pop(key, None)

                save_llm_config(
                    home=Path(tmp),
                    provider="anthropic",
                    model="claude-3-7-sonnet",
                    fallbacks=[
                        " openrouter/openai/gpt-4o-mini ",
                        "openrouter/openai/gpt-4o-mini",
                        "claude/claude-3-7-sonnet",
                        "anthropic/claude-3-7-sonnet",
                    ],
                )
                cfg = load_config()

                self.assertEqual(
                    cfg.llm.fallbacks,
                    ("openrouter/openai/gpt-4o-mini", "anthropic/claude-3-7-sonnet"),
                )
        finally:
            for key, value in old_values.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    def test_save_llm_config_rejects_unknown_provider_and_malformed_fallbacks(self):
        from ares.config.loader import save_llm_config

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                save_llm_config(home=Path(tmp), provider="notreal", model="demo")
            with self.assertRaises(ValueError):
                save_llm_config(home=Path(tmp), provider="openai", model="demo", fallbacks=["openrouter/"])

    def test_switching_from_native_to_openrouter_restores_provider_default_base_url(self):
        from ares.config.loader import load_config, save_llm_config
        from ares.llm.providers import DEFAULT_OPENROUTER_BASE_URL

        with tempfile.TemporaryDirectory() as tmp:
            save_llm_config(home=Path(tmp), provider="anthropic", model="claude-3-7-sonnet", openai_base_url="")
            save_llm_config(home=Path(tmp), provider="openrouter")
            cfg = load_config(Path(tmp))

        self.assertEqual(cfg.llm.provider, "openrouter")
        self.assertEqual(cfg.llm.openai_base_url, DEFAULT_OPENROUTER_BASE_URL)


if __name__ == "__main__":
    unittest.main()
