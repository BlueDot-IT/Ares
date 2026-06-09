import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ares.prompt_ui import Choice, ask_text, confirm, select_one


class PromptUITests(unittest.TestCase):
    def test_select_one_non_tty_accepts_numeric_choice_and_returns_internal_value(self):
        outputs: list[str] = []
        responses = iter(["2"])

        selected = select_one(
            "Model profile",
            choices=[
                Choice(value="local", label="Local endpoint", hint="LM Studio or llama.cpp"),
                Choice(value="openai", label="OpenAI cloud", hint="Known endpoint"),
            ],
            default="local",
            use_tty=False,
            input_fn=lambda prompt: next(responses),
            output_fn=outputs.append,
        )

        self.assertEqual(selected, "openai")
        joined = "\n".join(outputs)
        self.assertIn("1. Local endpoint", joined)
        self.assertIn("2. OpenAI cloud", joined)
        self.assertIn("Known endpoint", joined)

    def test_select_one_can_accept_internal_value_when_labels_are_different(self):
        selected = select_one(
            "Gateway mode",
            choices=[
                Choice(value="loopback", label="Loopback only"),
                Choice(value="exposed", label="Remote / exposed"),
            ],
            default="loopback",
            use_tty=False,
            input_fn=lambda prompt: "exposed",
            output_fn=lambda text: None,
        )

        self.assertEqual(selected, "exposed")

    def test_confirm_non_tty_uses_default_and_explicit_yes(self):
        defaulted = confirm(
            "Use default endpoint?",
            default=False,
            use_tty=False,
            input_fn=lambda prompt: "",
            output_fn=lambda text: None,
        )
        explicit = confirm(
            "Sign in now?",
            default=False,
            use_tty=False,
            input_fn=lambda prompt: "y",
            output_fn=lambda text: None,
        )

        self.assertFalse(defaulted)
        self.assertTrue(explicit)

    def test_ask_text_non_tty_returns_default_on_blank_input(self):
        value = ask_text(
            "Model name",
            default="gpt-4.1-mini",
            use_tty=False,
            input_fn=lambda prompt: "",
            output_fn=lambda text: None,
        )

        self.assertEqual(value, "gpt-4.1-mini")

    def test_hidden_ask_text_non_tty_uses_scripted_input(self):
        value = ask_text(
            "Operator token",
            default="generated-default",
            hide_input=True,
            use_tty=False,
            input_fn=lambda prompt: "operator-secret",
            output_fn=lambda text: None,
        )

        self.assertEqual(value, "operator-secret")


if __name__ == "__main__":
    unittest.main()
