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

    def test_load_config_defaults_ui_theme_to_ember(self):
        from ares.config.loader import load_config

        keys = ["ARES_HOME", "ARES_UI_THEME"]
        old_values = {key: os.environ.get(key) for key in keys}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["ARES_HOME"] = tmp
                os.environ.pop("ARES_UI_THEME", None)

                cfg = load_config()

                self.assertEqual(cfg.ui.theme, "ember")
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

    def test_persisted_config_file_is_private_and_generates_gateway_token_when_auth_enabled(self):
        from ares.config.loader import load_config, save_gateway_config

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = save_gateway_config(home=home, mode="exposed", auth_enabled=True)
            cfg = load_config(home)

            config_mode = path.stat().st_mode & 0o777
            home_mode = home.stat().st_mode & 0o777

        self.assertEqual(config_mode, 0o600)
        self.assertEqual(home_mode, 0o700)
        self.assertTrue(cfg.gateway.auth_enabled)
        self.assertTrue(cfg.gateway.operator_token)

    def test_provider_catalog_exposes_endpoint_and_auth_capabilities(self):
        from ares.llm.provider_catalog import get_provider_choice, list_provider_choices

        keys = [choice.key for choice in list_provider_choices()]

        self.assertEqual(keys, ["local", "openai", "openrouter", "anthropic", "gemini", "custom"])
        self.assertEqual(get_provider_choice("local").endpoint_mode, "editable")
        self.assertEqual(get_provider_choice("local").default_endpoint, "http://127.0.0.1:1234/v1")
        self.assertEqual(get_provider_choice("openai").endpoint_mode, "hidden")
        self.assertEqual(get_provider_choice("openai").default_endpoint, "https://api.openai.com/v1")
        self.assertEqual(get_provider_choice("openrouter").endpoint_mode, "hidden")
        self.assertEqual(get_provider_choice("openrouter").default_endpoint, "https://openrouter.ai/api/v1")
        self.assertEqual(get_provider_choice("anthropic").endpoint_mode, "native")
        self.assertEqual(get_provider_choice("gemini").endpoint_mode, "native")
        self.assertEqual(get_provider_choice("custom").endpoint_mode, "editable")
        self.assertEqual(get_provider_choice("gemini").auth_methods, ("api-key", "oauth"))
        self.assertEqual(get_provider_choice("anthropic").auth_methods, ("api-key",))
        self.assertEqual(get_provider_choice("openrouter").auth_methods, ("api-key",))

    def test_named_openai_profile_persists_expected_cloud_defaults(self):
        from ares.config.loader import apply_llm_profile, load_config

        with tempfile.TemporaryDirectory() as tmp:
            apply_llm_profile(home=Path(tmp), profile="openai")
            cfg = load_config(Path(tmp))

        self.assertEqual(cfg.llm.provider, "openai")
        self.assertEqual(cfg.llm.model, "gpt-4.1-mini")
        self.assertEqual(cfg.llm.openai_base_url, "https://api.openai.com/v1")

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

    def test_load_config_persists_oauth_auth_mode_and_settings(self):
        from ares.config.loader import load_config, save_llm_config

        with tempfile.TemporaryDirectory() as tmp:
            save_llm_config(
                home=Path(tmp),
                provider="gemini",
                model="gemini-2.5-pro",
                auth_mode="oauth",
                oauth_token_command="gcloud auth application-default print-access-token",
                oauth_project="demo-project",
                oauth_location="us-central1",
            )
            cfg = load_config(Path(tmp))

        self.assertEqual(cfg.llm.auth_mode, "oauth")
        self.assertEqual(cfg.llm.oauth_token_command, "gcloud auth application-default print-access-token")
        self.assertEqual(cfg.llm.oauth_project, "demo-project")
        self.assertEqual(cfg.llm.oauth_location, "us-central1")

    def test_switching_auth_mode_back_to_api_key_clears_oauth_settings(self):
        from ares.config.loader import load_config, save_llm_config

        with tempfile.TemporaryDirectory() as tmp:
            save_llm_config(
                home=Path(tmp),
                provider="openai",
                model="gpt-4.1-mini",
                auth_mode="oauth",
                oauth_token_command="print-openai-token",
                oauth_project="demo-project",
                oauth_location="global",
            )
            save_llm_config(home=Path(tmp), auth_mode="api-key")
            cfg = load_config(Path(tmp))

        self.assertEqual(cfg.llm.auth_mode, "api-key")
        self.assertEqual(cfg.llm.oauth_token_command, "")
        self.assertEqual(cfg.llm.oauth_project, "")
        self.assertEqual(cfg.llm.oauth_location, "")


if __name__ == "__main__":
    unittest.main()
