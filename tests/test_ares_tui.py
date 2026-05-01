import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class AresTuiTests(unittest.TestCase):
    def test_build_startup_hero_uses_requested_large_ascii_banner_block(self):
        from ares.tui import build_startup_hero

        hero = build_startup_hero(width=120)
        lines = hero.splitlines()
        banner_top = next(line for line in lines if "        ##                                                 ##" in line)
        banner_mid = next(line for line in lines if "###  /###     /##       /###" in line)
        banner_tail = next(line for line in lines if "/######  /#" in line)

        self.assertIn("        ##                                                 ##", hero)
        self.assertIn("     /####                                              /####", hero)
        self.assertIn("###  /###     /##       /###", hero)
        self.assertIn("/########    ##     ## ########  ##    ##      ##", hero)
        self.assertIn("/######  /#", hero)
        self.assertNotIn("MMP\"\"\"\"\"\"\"MM", hero)
        self.assertNotIn("=%@@@@@@@@#", hero)
        self.assertLess(hero.index("        ##                                                 ##"), hero.index("AUTONOMOUS PENTEST OPERATIONS"))
        self.assertLess(lines.index(banner_top), lines.index(banner_mid))
        self.assertLess(lines.index(banner_mid), lines.index(banner_tail))
        self.assertIn("AUTONOMOUS PENTEST OPERATIONS", hero)
        self.assertIn("CYBERSECURITY OPERATOR SHELL", hero)
        self.assertIn("Type /help or describe the task", hero)
        self.assertNotIn("╔", hero)

    def test_build_startup_hero_preserves_ascii_banner_on_narrow_terminals(self):
        from ares.tui import build_startup_hero

        hero = build_startup_hero(width=80)

        self.assertIn("        ##                                                 ##", hero)
        self.assertIn("###  /###     /##       /###", hero)
        self.assertNotEqual(hero.splitlines()[1].strip(), "ARES")

    def test_session_detail_view_shows_evidence_and_tool_history(self):
        from ares.state.db import StateDB
        from ares.tui import build_session_detail_text

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = StateDB(root / "state.db")
            session_id = db.create_session(prompt="enumerate web", target="127.0.0.1", model="unit-model", mode="safe-active")
            db.record_host(session_id, "127.0.0.1", hostname="localhost")
            db.record_service(session_id, "127.0.0.1", port=443, protocol="tcp", service="https", product="nginx")
            db.record_tool_call(session_id=session_id, tool="nmap_basic", args={"target": "127.0.0.1"}, status="ok", result={"stdout": "443/tcp open https"}, duration_ms=18)
            db.record_message(session_id, "assistant", "Found HTTPS exposed")
            db.finish_session(session_id, "completed")

            detail = build_session_detail_text(db, session_id)

        self.assertIn("Session Detail", detail)
        self.assertIn("prompt: enumerate web", detail)
        self.assertIn("127.0.0.1 (localhost)", detail)
        self.assertIn("443/tcp https - nginx", detail)
        self.assertIn("nmap_basic [ok] 18ms", detail)
        self.assertIn("messages: 1", detail)

    def test_message_trace_view_shows_recent_conversation_and_tool_results(self):
        from ares.state.db import StateDB
        from ares.tui import build_message_trace_text

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = StateDB(root / "state.db")
            session_id = db.create_session(prompt="fingerprint host", target="127.0.0.1", model="unit-model", mode="safe-active")
            db.record_message(session_id, "user", "Target: 127.0.0.1")
            db.record_message(session_id, "assistant", "Running passive discovery")
            db.record_tool_call(session_id=session_id, tool="dns_lookup", args={"host": "localhost"}, status="ok", result={"summary": "localhost resolves to 127.0.0.1"}, duration_ms=5)
            db.finish_session(session_id, "completed")

            trace = build_message_trace_text(db, session_id)

        self.assertIn("Message Trace", trace)
        self.assertIn("[user] Target: 127.0.0.1", trace)
        self.assertIn("[assistant] Running passive discovery", trace)
        self.assertIn("dns_lookup [ok] 5ms", trace)
        self.assertIn("localhost resolves to 127.0.0.1", trace)

    def test_build_live_activity_text_shows_running_job_and_recent_events(self):
        from ares.tui import BackgroundRunJob, build_live_activity_text

        job = BackgroundRunJob(prompt="enumerate host", target="127.0.0.1")
        job.status = "running"
        job.session_id = 7
        job.events.extend(
            [
                {"type": "session_started", "message": "session 7 started"},
                {"type": "tool_result", "message": "nmap_basic ok", "tool": "nmap_basic"},
            ]
        )

        text = build_live_activity_text(job)

        self.assertIn("Live Activity", text)
        self.assertIn("status: running", text)
        self.assertIn("session_id: 7", text)
        self.assertIn("nmap_basic ok", text)

    def test_background_run_controller_captures_events_and_completion(self):
        from ares.tui import BackgroundRunController

        def fake_run_once(**kwargs):
            kwargs["session_started_callback"](42)
            kwargs["event_callback"]({"type": "tool_result", "tool": "nmap_basic", "message": "nmap_basic ok"})
            kwargs["event_callback"]({"type": "final_response", "final_response": "complete", "message": "complete"})
            return SimpleNamespace(final_response="complete", stop_reason="final_response", tool_results=[])

        controller = BackgroundRunController(run_callable=fake_run_once)
        job = controller.start_job(prompt="enumerate host", target="127.0.0.1")
        job.thread.join(timeout=2)

        self.assertEqual(job.status, "completed")
        self.assertEqual(job.session_id, 42)
        self.assertEqual(job.final_response, "complete")
        self.assertTrue(any(event["type"] == "tool_result" for event in job.events))
        self.assertEqual(job.events[-1]["type"], "session_finished")

    def test_build_help_text_lists_chat_slash_commands(self):
        from ares.tui import build_help_text

        help_text = build_help_text()

        self.assertIn("Slash Commands", help_text)
        self.assertIn("/help", help_text)
        self.assertIn("/commands", help_text)
        self.assertIn("/tools", help_text)
        self.assertIn("/sessions", help_text)
        self.assertIn("/doctor", help_text)
        self.assertIn("/model", help_text)
        self.assertIn("/theme", help_text)
        self.assertIn("/scope", help_text)
        self.assertIn("/clear", help_text)
        self.assertIn("PageUp/PageDown", help_text)
        self.assertIn("Home jumps to oldest", help_text)
        self.assertIn("/quit", help_text)

    def test_build_operator_shell_text_renders_chat_transcript_and_inline_tool_chain(self):
        from ares.tui import BackgroundRunJob, build_operator_shell_text

        job = BackgroundRunJob(prompt="Enumerate perimeter", target="corp.example")
        job.status = "running"
        shell = build_operator_shell_text(
            transcript=[
                {"kind": "user", "text": "Enumerate the external perimeter."},
                {"kind": "assistant", "text": "Starting reconnaissance against the authorized target."},
                {"kind": "tool_call", "text": "nmap_basic {\"target\": \"corp.example\"}"},
                {"kind": "tool_result", "text": "443/tcp open https"},
                {"kind": "assistant", "text": "HTTPS is exposed. Next I would fingerprint the service."},
            ],
            input_buffer="/tools",
            status_message="running reconnaissance",
            target="corp.example",
            selected_session_id=12,
            background_job=job,
            width=100,
            yolo_mode=True,
        )

        self.assertIn("        ##                                                 ##", shell)
        self.assertIn("target: corp.example", shell)
        self.assertIn("scope: private", shell)
        self.assertIn("commands: type /commands for a list", shell)
        self.assertNotIn("/sessions /inspect /messages", shell)
        self.assertIn("theme: ember", shell)
        self.assertIn("session: 12", shell)
        self.assertIn("job: running", shell)
        self.assertIn("yolo: ON", shell)
        self.assertIn("operator > Enumerate the external perimeter.", shell)
        self.assertIn("ares     > Starting reconnaissance against the authorized target.", shell)
        self.assertIn("tool     > nmap_basic {\"target\": \"corp.example\"}", shell)
        self.assertIn("result   > 443/tcp open https", shell)
        self.assertIn("ember    > /tools", shell)
        self.assertNotIn("OPERATOR CONSOLE", shell)

    def test_build_operator_shell_text_can_render_alternate_theme_chrome(self):
        from ares.tui import build_operator_shell_text

        shell = build_operator_shell_text(
            transcript=[{"kind": "assistant", "text": "Theme check"}],
            input_buffer="/theme",
            status_message="ready",
            target=None,
            selected_session_id=None,
            background_job=None,
            width=90,
            theme_name="matrix",
        )

        self.assertIn("theme: matrix", shell)
        self.assertIn("matrix   > /theme", shell)
        self.assertIn("┄", shell)
        self.assertNotIn("prompt   > /theme", shell)

    def test_yolo_command_toggles_operator_mode(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        self.assertFalse(tui.state.approve_dangerous)

        tui._handle_slash_command("/yolo")
        self.assertTrue(tui.state.approve_dangerous)
        self.assertIn("dangerous-tool approval enabled", tui.state.transcript[-1]["text"])

        tui._handle_slash_command("/yolo")
        self.assertFalse(tui.state.approve_dangerous)
        self.assertIn("dangerous-tool approval disabled", tui.state.transcript[-1]["text"])

    def test_scope_command_toggles_public_target_policy_for_authorized_vps(self):
        from ares.tui import AresTUI

        old_home = os.environ.get("APP_HOME")
        old_scope = os.environ.get("ALLOW_PRIVATE_ONLY")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["APP_HOME"] = tmp
                os.environ["ALLOW_PRIVATE_ONLY"] = "true"
                tui = AresTUI()

                tui._handle_slash_command("/scope public")

                self.assertEqual(os.environ["ALLOW_PRIVATE_ONLY"], "false")
                self.assertFalse(tui.config.policy.allow_private_only)
                self.assertIn("public targets allowed", tui.state.transcript[-1]["text"])

                shell = tui._frame_text(width=100)
                self.assertIn("scope: public", shell)

                tui._handle_slash_command("/scope private")

                self.assertEqual(os.environ["ALLOW_PRIVATE_ONLY"], "true")
                self.assertTrue(tui.config.policy.allow_private_only)
                self.assertIn("private-only", tui.state.transcript[-1]["text"])

                tui._handle_slash_command("/scope")
                self.assertEqual(os.environ["ALLOW_PRIVATE_ONLY"], "false")
                self.assertFalse(tui.config.policy.allow_private_only)

                tui._handle_slash_command("/scope banana")
                self.assertEqual(os.environ["ALLOW_PRIVATE_ONLY"], "false")
                self.assertIn("usage: /scope", tui.state.transcript[-1]["text"])
        finally:
            if old_home is None:
                os.environ.pop("APP_HOME", None)
            else:
                os.environ["APP_HOME"] = old_home
            if old_scope is None:
                os.environ.pop("ALLOW_PRIVATE_ONLY", None)
            else:
                os.environ["ALLOW_PRIVATE_ONLY"] = old_scope

    def test_commands_alias_shows_help_text(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        tui._handle_slash_command("/commands")

        self.assertIn("Slash Commands", tui.state.transcript[-1]["text"])
        self.assertIn("/scope", tui.state.transcript[-1]["text"])

    def test_model_command_updates_persisted_settings_and_reports_current_model(self):
        from ares.config.loader import AppConfig, LLMConfig, PolicyConfig, load_config
        from ares.state.db import StateDB
        from ares.tui import AresTUI

        old_home = os.environ.get("APP_HOME")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["APP_HOME"] = tmp
                root = Path(tmp)
                tui = AresTUI()
                tui.config = AppConfig(
                    home=root,
                    llm=LLMConfig(provider="openai", model="initial-model", openai_base_url="http://127.0.0.1:1234/v1"),
                    policy=PolicyConfig(),
                )
                tui.state_db = StateDB(root / "state.db")

                tui._handle_slash_command("/model set redteam-model")
                tui._handle_slash_command("/model provider openrouter")
                tui._handle_slash_command("/model base-url http://127.0.0.1:9000/v1")
                tui._handle_slash_command("/model")

                cfg = load_config()
                self.assertEqual(cfg.llm.model, "redteam-model")
                self.assertEqual(cfg.llm.provider, "openrouter")
                self.assertEqual(cfg.llm.openai_base_url, "http://127.0.0.1:9000/v1")
                self.assertIn("model set: redteam-model", tui.state.transcript[-4]["text"])
                self.assertIn("provider set: openrouter", tui.state.transcript[-3]["text"])
                self.assertIn("base_url set: http://127.0.0.1:9000/v1", tui.state.transcript[-2]["text"])
                self.assertIn("provider: openrouter", tui.state.transcript[-1]["text"])
                self.assertIn("model: redteam-model", tui.state.transcript[-1]["text"])
        finally:
            if old_home is None:
                os.environ.pop("APP_HOME", None)
            else:
                os.environ["APP_HOME"] = old_home

    def test_model_profile_and_theme_commands_persist_settings_and_streamed_text_is_folded_into_transcript(self):
        from ares.config.loader import load_config
        from ares.tui import AresTUI

        old_home = os.environ.get("APP_HOME")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                os.environ["APP_HOME"] = tmp
                tui = AresTUI()

                tui._handle_slash_command("/model profile openrouter")
                tui._handle_slash_command("/theme set matrix")
                tui._handle_runtime_event({"type": "assistant_delta", "provider": "openrouter", "text": "Scanning "})
                self.assertEqual(tui.state.transcript[2]["kind"], "assistant_stream")
                self.assertEqual(tui.state.transcript[2]["text"], "[openrouter] Scanning ")
                tui._handle_runtime_event({"type": "assistant_delta", "provider": "openrouter", "text": " authorized scope..."})
                tui._handle_runtime_event({"type": "final_response", "final_response": "Scanning authorized scope..."})
                tui._handle_slash_command("/theme")

                cfg = load_config()
                self.assertEqual(cfg.llm.provider, "openrouter")
                self.assertEqual(cfg.ui.theme, "matrix")
                self.assertIn("profile applied: openrouter", tui.state.transcript[0]["text"])
                self.assertIn("theme set: matrix", tui.state.transcript[1]["text"])
                self.assertEqual(tui.state.transcript[2]["kind"], "assistant")
                self.assertEqual(tui.state.transcript[2]["text"], "Scanning authorized scope...")
                self.assertIn("Themes", tui.state.transcript[-1]["text"])
                self.assertIn("matrix", tui.state.transcript[-1]["text"])
        finally:
            if old_home is None:
                os.environ.pop("APP_HOME", None)
            else:
                os.environ["APP_HOME"] = old_home

    def test_theme_preview_command_renders_selected_theme_preview(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        tui._handle_slash_command("/theme preview ember")

        self.assertIn("Theme Preview", tui.state.transcript[-1]["text"])
        self.assertIn("Ember", tui.state.transcript[-1]["text"])
        self.assertIn("ember    > /theme preview ember", tui.state.transcript[-1]["text"])
        self.assertIn("palette:", tui.state.transcript[-1]["text"])

    def test_tui_suppresses_consecutive_duplicate_assistant_messages(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        tui._append_transcript("assistant", "Same final response")
        tui._append_transcript("assistant", "Same final response")

        self.assertEqual(tui.state.transcript, [{"kind": "assistant", "text": "Same final response"}])

    def test_tui_run_uses_prompt_toolkit_shell_by_default(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        calls: list[str] = []
        tui._run_prompt_toolkit = lambda: calls.append("prompt_toolkit")

        tui.run()

        self.assertEqual(calls, ["prompt_toolkit"])

    def test_tui_run_falls_back_to_curses_when_prompt_toolkit_unavailable(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        calls: list[str] = []
        tui._run_prompt_toolkit = lambda: (_ for _ in ()).throw(ImportError("missing prompt_toolkit"))
        with patch("ares.tui.curses.wrapper", side_effect=lambda loop: calls.append("curses")):
            tui.run()

        self.assertEqual(calls, ["curses"])

    def test_prompt_toolkit_body_text_keeps_recent_transcript_visible_on_short_terminals(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        tui._append_transcript("user", "yo")
        tui._append_transcript("assistant", "Visible final line")

        body = tui._prompt_toolkit_body_text(columns=100, rows=10)

        self.assertIn("operator > yo", body)
        self.assertIn("ares     > Visible final line", body)
        self.assertNotIn("AUTONOMOUS PENTEST OPERATIONS", body)
        self.assertNotIn("ember    >", body)

    def test_prompt_toolkit_body_fragments_apply_theme_roles(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        tui._append_transcript("user", "yo")
        tui._append_transcript("assistant", "Visible final line")

        fragments = tui._prompt_toolkit_body_fragments(columns=100, rows=10)

        self.assertIn(("class:user", "operator > yo"), fragments)
        self.assertIn(("class:assistant", "ares     > Visible final line"), fragments)
        self.assertTrue(any(style == "class:separator" for style, _ in fragments))

    def test_prompt_toolkit_body_can_scroll_back_and_return_to_latest(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        for index in range(30):
            tui._append_transcript("assistant", f"line-{index:02d}")

        latest = tui._prompt_toolkit_body_text(columns=100, rows=8)
        self.assertIn("line-29", latest)

        tui._scroll_body(delta=8, columns=100, rows=8)
        older = tui._prompt_toolkit_body_text(columns=100, rows=8)

        self.assertNotIn("line-29", older)
        self.assertIn("line-21", older)

        tui._scroll_body(delta=-8, columns=100, rows=8)
        latest_again = tui._prompt_toolkit_body_text(columns=100, rows=8)

        self.assertIn("line-29", latest_again)

    def test_prompt_toolkit_shell_binds_page_keys_for_scrollback(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        with patch("prompt_toolkit.application.Application") as app_cls:
            tui._run_prompt_toolkit()

        bindings = app_cls.call_args.kwargs["key_bindings"].bindings
        keys = {tuple(getattr(key, "value", str(key)) for key in binding.keys) for binding in bindings}
        self.assertIn(("pageup",), keys)
        self.assertIn(("pagedown",), keys)
        self.assertIn(("end",), keys)

    def test_prompt_toolkit_style_uses_active_theme_palette(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        style = tui._prompt_toolkit_style()

        style_map = dict(style.style_rules)
        self.assertIn("assistant", style_map)
        self.assertIn("ansiyellow", style_map["assistant"])
        self.assertIn("tool", style_map)
        self.assertIn("ansired", style_map["tool"])

    def test_prompt_toolkit_shell_constructs_application_with_theme_style(self):
        from ares.tui import AresTUI

        tui = AresTUI()
        with patch("prompt_toolkit.application.Application") as app_cls:
            app = app_cls.return_value
            tui._run_prompt_toolkit()

        app_cls.assert_called_once()
        style = app_cls.call_args.kwargs.get("style")
        self.assertIsNotNone(style)
        self.assertEqual(type(style).__name__, "DynamicStyle")
        app.run.assert_called_once()

    def test_select_neighbor_session_id_clamps_to_known_session_ids(self):
        from ares.tui import select_neighbor_session_id

        self.assertEqual(select_neighbor_session_id([3, 8, 13], None, 1), 13)
        self.assertEqual(select_neighbor_session_id([3, 8, 13], 8, 1), 13)
        self.assertEqual(select_neighbor_session_id([3, 8, 13], 8, -1), 3)
        self.assertEqual(select_neighbor_session_id([3, 8, 13], 999, -1), 13)
        self.assertIsNone(select_neighbor_session_id([], 1, 1))


if __name__ == "__main__":
    unittest.main()
