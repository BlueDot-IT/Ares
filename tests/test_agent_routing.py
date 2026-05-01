import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AgentRoutingTests(unittest.TestCase):
    def test_agent_router_matches_routes_and_applies_profile_overrides(self):
        from ares.config.loader import (
            AgentProfileConfig,
            AgentRouteConfig,
            AgentsConfig,
            AppConfig,
            LLMConfig,
            PolicyConfig,
        )
        from ares.routing import AgentRouter, apply_agent_profile

        config = AppConfig(
            home=Path("/tmp/ares-routing"),
            llm=LLMConfig(provider="openai", model="base-model", openai_base_url="http://127.0.0.1:1234/v1"),
            policy=PolicyConfig(max_risk="active", allow_private_only=True, roe_profile="safe-active"),
            agents=AgentsConfig(
                default_agent="default",
                profiles={
                    "default": AgentProfileConfig(name="default"),
                    "web": AgentProfileConfig(
                        name="web",
                        provider="openrouter",
                        model="web-model",
                        openai_base_url="https://openrouter.ai/api/v1",
                        max_risk="passive",
                        allow_private_only=False,
                        enabled_toolsets=("web",),
                    ),
                },
                routes=(AgentRouteConfig(agent="web", target_schemes=("http", "https")),),
            ),
        )

        router = AgentRouter(config.agents)
        resolution = router.resolve(target="https://example.com")
        effective = apply_agent_profile(config, resolution)

        self.assertEqual(resolution.agent_name, "web")
        self.assertEqual(effective.llm.provider, "openrouter")
        self.assertEqual(effective.llm.model, "web-model")
        self.assertEqual(effective.policy.max_risk, "passive")
        self.assertFalse(effective.policy.allow_private_only)
        self.assertEqual(effective.agents.active_agent, "web")

    def test_agent_router_can_match_prompt_and_roe_profile_and_prompt_prefix_flows_into_runtime(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import (
            AgentProfileConfig,
            AgentRouteConfig,
            AgentsConfig,
            AppConfig,
            LLMConfig,
            PolicyConfig,
        )
        from ares.routing import AgentRouter
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        class CapturingModel:
            def __init__(self):
                self.messages = []

            def complete(self, messages, tools):
                self.messages = list(messages)
                return ModelResponse(final_text="done")

        registry = ToolRegistry()
        registry.register(
            name="web_probe",
            toolset="web",
            risk="passive",
            schema={"name": "web_probe", "description": "web", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="active", allow_private_only=True, roe_profile="safe-active"),
                agents=AgentsConfig(
                    default_agent="default",
                    profiles={
                        "default": AgentProfileConfig(name="default"),
                        "web": AgentProfileConfig(
                            name="web",
                            enabled_toolsets=("web",),
                            allow_private_only=False,
                            prompt_prefix="[web-recon] ",
                            memory_tags=("recon", "external"),
                        ),
                    },
                    routes=(
                        AgentRouteConfig(
                            agent="web",
                            prompt_contains=("recon",),
                            roe_profiles=("safe-active",),
                        ),
                    ),
                ),
            )
            router = AgentRouter(config.agents)
            resolution = router.resolve(prompt="recon the target", target="https://example.com", roe_profile="safe-active")
            model = CapturingModel()
            result = run_once(
                prompt="recon the target",
                target="https://example.com",
                config=config,
                model=model,
                registry=registry,
            )

        self.assertEqual(resolution.agent_name, "web")
        self.assertEqual(resolution.reason, "route")
        self.assertEqual(result.final_response, "done")
        user_message = [message for message in model.messages if message.get("role") == "user"][-1]["content"]
        self.assertIn("Task: [web-recon] recon the target", user_message)

    def test_run_once_selects_agent_profile_records_agent_and_filters_visible_toolsets(self):
        from ares.agent.runtime import ModelResponse
        from ares.config.loader import (
            AgentProfileConfig,
            AgentRouteConfig,
            AgentsConfig,
            AppConfig,
            LLMConfig,
            PolicyConfig,
        )
        from ares.run import run_once
        from ares.state.db import StateDB
        from ares.tools.registry import ToolRegistry

        class CapturingModel:
            def __init__(self):
                self.tool_names = []

            def complete(self, messages, tools):
                self.tool_names = [tool["function"]["name"] for tool in tools]
                return ModelResponse(final_text="done")

        registry = ToolRegistry()
        registry.register(
            name="web_probe",
            toolset="web",
            risk="passive",
            schema={"name": "web_probe", "description": "web", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        registry.register(
            name="internal_probe",
            toolset="internal",
            risk="passive",
            schema={"name": "internal_probe", "description": "internal", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        events = []
        model = CapturingModel()

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(model="unit-model"),
                policy=PolicyConfig(max_risk="active", allow_private_only=True),
                agents=AgentsConfig(
                    default_agent="default",
                    profiles={
                        "default": AgentProfileConfig(name="default"),
                        "web": AgentProfileConfig(name="web", enabled_toolsets=("web",), allow_private_only=False),
                    },
                    routes=(AgentRouteConfig(agent="web", target_schemes=("http", "https")),),
                ),
            )
            result = run_once(
                prompt="inspect target",
                target="https://example.com",
                config=config,
                model=model,
                registry=registry,
                event_callback=events.append,
            )
            db = StateDB(Path(tmp) / "state.db")
            session = db.list_sessions()[0]

        self.assertEqual(result.final_response, "done")
        self.assertEqual(model.tool_names, ["web_probe"])
        self.assertEqual(session["agent"], "web")
        self.assertEqual(events[0]["type"], "session_started")
        self.assertEqual(events[1]["type"], "route_selected")
        self.assertEqual(events[1]["agent"], "web")

    def test_load_config_enables_default_darkweb_agent_and_route_when_onionclaw_enabled(self):
        from ares.config.loader import load_config, save_onionclaw_config
        from ares.routing import AgentRouter, apply_agent_profile

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            save_onionclaw_config(home=home, enabled=True, repo_path="/opt/onionclaw")
            config = load_config(home)
            router = AgentRouter(config.agents)
            resolution = router.resolve(prompt="inspect hidden service", target="http://examplehiddenservice.onion")
            effective = apply_agent_profile(config, resolution)

        self.assertIn("darkweb", config.agents.profiles)
        self.assertEqual(resolution.agent_name, "darkweb")
        self.assertEqual(resolution.reason, "route")
        self.assertEqual(effective.agents.active_agent, "darkweb")
        self.assertFalse(effective.policy.allow_private_only)
        self.assertEqual(effective.onionclaw.repo_path, "/opt/onionclaw")
        self.assertEqual(effective.agents.profiles["darkweb"].enabled_toolsets, ("onionclaw",))

    def test_onionclaw_prompt_keywords_do_not_disable_private_only_without_onion_target(self):
        from ares.config.loader import load_config, save_onionclaw_config
        from ares.routing import AgentRouter, apply_agent_profile

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            save_onionclaw_config(home=home, enabled=True, repo_path="/opt/onionclaw")
            config = load_config(home)
            router = AgentRouter(config.agents)
            resolution = router.resolve(prompt="research darkweb brokers", target="https://example.com")
            effective = apply_agent_profile(config, resolution)

        self.assertEqual(resolution.agent_name, "default")
        self.assertTrue(effective.policy.allow_private_only)


if __name__ == "__main__":
    unittest.main()
