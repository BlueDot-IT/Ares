import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class RunApprovalAndHelpersTests(unittest.TestCase):
    def test_run_once_denies_dangerous_tool_by_default_and_allows_when_flag_set(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        def make_model():
            class FakeModel:
                def __init__(self):
                    self.responses = [
                        ModelResponse(tool_calls=[ToolCall(name="exploit_tool", args={"target": "127.0.0.1"})]),
                        ModelResponse(final_text="done"),
                    ]

                def complete(self, messages, tools):
                    return self.responses.pop(0)
            return FakeModel()

        registry = ToolRegistry()
        registry.register(
            name="exploit_tool",
            toolset="unit",
            risk="exploit",
            schema={"name": "exploit_tool", "description": "exploit", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"ok": True},
        )
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(home=Path(tmp), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="exploit"))
            denied = run_once(prompt="run exploit", target="127.0.0.1", config=config, model=make_model(), registry=registry)
            allowed = run_once(prompt="run exploit", target="127.0.0.1", config=config, model=make_model(), registry=registry, approve_dangerous=True)

        self.assertEqual(denied.tool_results[0].status, "error")
        self.assertIn("approval denied", denied.tool_results[0].error)
        self.assertEqual(allowed.tool_results[0].status, "ok")

    def test_run_once_policy_override_wins_over_profile_allow_private_only(self):
        from ares.agent.runtime import RuntimeResult
        from ares.config.loader import AgentProfileConfig, AgentsConfig, AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        captured: dict[str, bool] = {}

        class FakeDispatcher:
            def __init__(self, *, registry, policy, **kwargs):
                captured["policy_allow_private_only"] = policy.allow_private_only

        class FakeRuntime:
            def __init__(self, **kwargs):
                pass

            def run(self, message):
                return RuntimeResult(
                    final_response="done",
                    stop_reason="done",
                    messages=[{"role": "assistant", "content": "done"}],
                    tool_results=[],
                )

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(
                home=Path(tmp),
                llm=LLMConfig(model="unit"),
                policy=PolicyConfig(max_risk="active", allow_private_only=True),
                agents=AgentsConfig(
                    default_agent="locked",
                    active_agent="locked",
                    profiles={
                        "default": AgentProfileConfig(name="default"),
                        "locked": AgentProfileConfig(name="locked", allow_private_only=True),
                    },
                ),
            )
            with patch("ares.run.ToolDispatcher", FakeDispatcher), patch("ares.run.AgentRuntime", FakeRuntime):
                result = run_once(
                    prompt="scope test",
                    target="127.0.0.1",
                    config=config,
                    model=object(),
                    registry=ToolRegistry(),
                    policy_allow_private_only=False,
                )

        self.assertEqual(result.final_response, "done")
        self.assertFalse(captured["policy_allow_private_only"])

    def test_build_registry_passes_policy_allow_private_only_to_ghostmcp_tools(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import build_registry

        captured: dict[str, bool | None] = {}

        def fake_register(registry, *, toolset="ghostmcp", runner=None, policy_allow_private_only=None):
            captured["policy_allow_private_only"] = policy_allow_private_only
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(home=Path(tmp), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="active", allow_private_only=False))
            with patch("ares.run.register_ghostmcp_tools", side_effect=fake_register), patch("ares.run.register_onionclaw_tools", return_value=0):
                build_registry(config)

        self.assertFalse(captured["policy_allow_private_only"])

    def test_run_once_emits_session_and_runtime_events(self):
        from ares.agent.runtime import ModelResponse, ToolCall
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import run_once
        from ares.tools.registry import ToolRegistry

        class FakeModel:
            def __init__(self):
                self.responses = [
                    ModelResponse(tool_calls=[ToolCall(name="echo_tool", args={"text": "hello"})]),
                    ModelResponse(final_text="done"),
                ]

            def complete(self, messages, tools):
                return self.responses.pop(0)

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: {"echo": args["text"]},
        )
        events = []
        session_ids = []

        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig(home=Path(tmp), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="passive"))
            result = run_once(
                prompt="say hello",
                target="127.0.0.1",
                config=config,
                model=FakeModel(),
                registry=registry,
                event_callback=events.append,
                session_started_callback=session_ids.append,
            )

        self.assertEqual(result.final_response, "done")
        self.assertEqual(len(session_ids), 1)
        self.assertEqual(events[0]["type"], "session_started")
        self.assertTrue(any(event["type"] == "tool_call" and event.get("tool") == "echo_tool" for event in events))
        self.assertTrue(any(event["type"] == "tool_result" and event.get("tool") == "echo_tool" for event in events))
        self.assertTrue(any(event["type"] == "final_response" and event.get("final_response") == "done" for event in events))
        self.assertEqual(events[-1]["type"], "session_finished")

    def test_doctor_snapshot_and_tool_list_helpers(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig
        from ares.run import build_doctor_snapshot, list_registered_tools
        from ares.tools.registry import ToolRegistry

        registry = ToolRegistry()
        registry.register(
            name="echo_tool",
            toolset="unit",
            risk="passive",
            schema={"name": "echo_tool", "description": "echo", "parameters": {"type": "object"}},
            handler=lambda args, **_: args,
        )
        config = AppConfig(home=Path("/tmp/ares-test"), llm=LLMConfig(model="unit"), policy=PolicyConfig(max_risk="passive"))

        tools = list_registered_tools(registry)
        snapshot = build_doctor_snapshot(config=config, registry=registry)

        self.assertEqual(tools[0]["name"], "echo_tool")
        self.assertEqual(tools[0]["risk"], "passive")
        self.assertEqual(snapshot["llm_model"], "unit")
        self.assertEqual(snapshot["registered_tools"], 1)


if __name__ == "__main__":
    unittest.main()
