from __future__ import annotations

import curses
import getpass
import sys
from dataclasses import dataclass
from typing import Callable

import typer


@dataclass(frozen=True)
class Choice:
    value: str
    label: str
    hint: str = ""


InputFn = Callable[[str], str]
OutputFn = Callable[[str], None]


def _default_input(prompt: str) -> str:
    return input(prompt)


def _default_output(text: str) -> None:
    typer.echo(text)


def _should_use_tty(use_tty: bool | None) -> bool:
    if use_tty is not None:
        return use_tty
    return bool(sys.stdin.isatty() and sys.stdout.isatty() and (sys.stderr.isatty() or True))


def ask_text(
    prompt: str,
    *,
    default: str = "",
    allow_empty: bool = False,
    hide_input: bool = False,
    use_tty: bool | None = None,
    input_fn: InputFn | None = None,
    output_fn: OutputFn | None = None,
) -> str:
    use_tty = _should_use_tty(use_tty)
    input_fn = input_fn or _default_input
    output_fn = output_fn or _default_output
    while True:
        suffix = f" [{default}]" if default else ""
        prompt_text = f"{prompt}{suffix}: "
        if hide_input and use_tty and input_fn is _default_input:
            raw = getpass.getpass(prompt_text)
        else:
            raw = input_fn(prompt_text)
        value = str(raw or "").strip()
        if value:
            return value
        if default:
            return default
        if allow_empty:
            return ""
        if not use_tty:
            output_fn("A value is required.")


def confirm(
    prompt: str,
    *,
    default: bool = False,
    use_tty: bool | None = None,
    input_fn: InputFn | None = None,
    output_fn: OutputFn | None = None,
) -> bool:
    input_fn = input_fn or _default_input
    output_fn = output_fn or _default_output
    use_tty = _should_use_tty(use_tty)
    default_hint = "Y/n" if default else "y/N"
    while True:
        raw = input_fn(f"{prompt} [{default_hint}]: ")
        normalized = str(raw or "").strip().lower()
        if not normalized:
            return default
        if normalized in {"y", "yes", "1", "true"}:
            return True
        if normalized in {"n", "no", "0", "false"}:
            return False
        if not use_tty:
            output_fn("Please answer y or n.")


def select_one(
    prompt: str,
    *,
    choices: list[Choice],
    default: str | None = None,
    use_tty: bool | None = None,
    input_fn: InputFn | None = None,
    output_fn: OutputFn | None = None,
) -> str:
    input_fn = input_fn or _default_input
    output_fn = output_fn or _default_output
    use_tty = _should_use_tty(use_tty)
    if use_tty:
        try:
            return _curses_select_one(prompt=prompt, choices=choices, default=default)
        except Exception:
            pass
    return _numbered_select_one(prompt=prompt, choices=choices, default=default, input_fn=input_fn, output_fn=output_fn)


def _numbered_select_one(
    *,
    prompt: str,
    choices: list[Choice],
    default: str | None,
    input_fn: InputFn,
    output_fn: OutputFn,
) -> str:
    index_by_value = {choice.value.lower(): position for position, choice in enumerate(choices, start=1)}
    index_by_label = {choice.label.lower(): position for position, choice in enumerate(choices, start=1)}
    default_index = index_by_value.get(str(default or "").strip().lower(), 1 if choices else 0)
    output_fn(prompt)
    for index, choice in enumerate(choices, start=1):
        suffix = f" - {choice.hint}" if choice.hint else ""
        output_fn(f"{index}. {choice.label}{suffix}")
    while True:
        raw = input_fn(f"Choose [default {default_index}]: ")
        normalized = str(raw or "").strip()
        if not normalized and default_index:
            return choices[default_index - 1].value
        if normalized.isdigit():
            selected_index = int(normalized)
            if 1 <= selected_index <= len(choices):
                return choices[selected_index - 1].value
        lowered = normalized.lower()
        mapped_index = index_by_value.get(lowered) or index_by_label.get(lowered)
        if mapped_index:
            return choices[mapped_index - 1].value
        output_fn("Invalid choice. Enter a number or an exact value.")


def _curses_select_one(*, prompt: str, choices: list[Choice], default: str | None) -> str:
    default_index = 0
    if default:
        for index, choice in enumerate(choices):
            if choice.value == default:
                default_index = index
                break

    def _run(stdscr: curses.window) -> str:
        curses.curs_set(0)
        selected = default_index
        while True:
            stdscr.erase()
            height, width = stdscr.getmaxyx()
            stdscr.addnstr(0, 0, prompt, max(1, width - 1), curses.A_BOLD)
            for row, choice in enumerate(choices, start=2):
                label = choice.label
                if choice.hint:
                    label = f"{label} - {choice.hint}"
                attr = curses.A_REVERSE if row - 2 == selected else curses.A_NORMAL
                stdscr.addnstr(row, 0, label, max(1, width - 1), attr)
            stdscr.refresh()
            key = stdscr.getch()
            if key in {curses.KEY_UP, ord("k")}:
                selected = (selected - 1) % len(choices)
            elif key in {curses.KEY_DOWN, ord("j")}:
                selected = (selected + 1) % len(choices)
            elif key in {10, 13, curses.KEY_ENTER}:
                return choices[selected].value
            elif ord("1") <= key <= ord(str(min(len(choices), 9))):
                candidate = key - ord("1")
                if 0 <= candidate < len(choices):
                    return choices[candidate].value

    return curses.wrapper(_run)
