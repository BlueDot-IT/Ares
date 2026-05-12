from __future__ import annotations

from dataclasses import dataclass


DEFAULT_THEME = "ember"


@dataclass(frozen=True)
class ThemeTone:
    fg: str
    bg: str = "default"
    attrs: tuple[str, ...] = ()

    def label(self) -> str:
        attr_suffix = f" {'+'.join(self.attrs)}" if self.attrs else ""
        return f"{self.fg}/{self.bg}{attr_suffix}"


@dataclass(frozen=True)
class ThemeSpec:
    name: str
    label: str
    separator: str
    prompt_prefix: str
    stream_prefix: str
    palette: dict[str, ThemeTone]


THEMES: dict[str, ThemeSpec] = {
    "midnight": ThemeSpec(
        name="midnight",
        label="Midnight",
        separator="─",
        prompt_prefix="prompt   > ",
        stream_prefix="stream   > ",
        palette={
            "hero": ThemeTone("cyan", attrs=("bold",)),
            "chrome": ThemeTone("blue", attrs=("bold",)),
            "status": ThemeTone("yellow"),
            "separator": ThemeTone("blue"),
            "user": ThemeTone("white", attrs=("bold",)),
            "assistant": ThemeTone("cyan"),
            "stream": ThemeTone("magenta"),
            "tool": ThemeTone("yellow", attrs=("bold",)),
            "result": ThemeTone("green"),
            "input": ThemeTone("white", attrs=("bold",)),
            "system": ThemeTone("red"),
        },
    ),
    "matrix": ThemeSpec(
        name="matrix",
        label="Matrix",
        separator="┄",
        prompt_prefix="matrix   > ",
        stream_prefix="signal   > ",
        palette={
            "hero": ThemeTone("green", attrs=("bold",)),
            "chrome": ThemeTone("green"),
            "status": ThemeTone("yellow"),
            "separator": ThemeTone("green"),
            "user": ThemeTone("white", attrs=("bold",)),
            "assistant": ThemeTone("green"),
            "stream": ThemeTone("green"),
            "tool": ThemeTone("yellow", attrs=("bold",)),
            "result": ThemeTone("green", attrs=("bold",)),
            "input": ThemeTone("white", attrs=("bold",)),
            "system": ThemeTone("magenta"),
        },
    ),
    "ember": ThemeSpec(
        name="ember",
        label="Ember",
        separator="═",
        prompt_prefix="ember    > ",
        stream_prefix="embers   > ",
        palette={
            "hero": ThemeTone("red", attrs=("bold",)),
            "chrome": ThemeTone("yellow", attrs=("bold",)),
            "status": ThemeTone("magenta"),
            "separator": ThemeTone("red"),
            "user": ThemeTone("white", attrs=("bold",)),
            "assistant": ThemeTone("yellow"),
            "stream": ThemeTone("magenta", attrs=("bold",)),
            "tool": ThemeTone("red", attrs=("bold",)),
            "result": ThemeTone("green"),
            "input": ThemeTone("white", attrs=("bold",)),
            "system": ThemeTone("cyan"),
        },
    ),
    "cobalt": ThemeSpec(
        name="cobalt",
        label="Cobalt",
        separator="━",
        prompt_prefix="cobalt   > ",
        stream_prefix="delta    > ",
        palette={
            "hero": ThemeTone("blue", attrs=("bold",)),
            "chrome": ThemeTone("cyan", attrs=("bold",)),
            "status": ThemeTone("white"),
            "separator": ThemeTone("blue"),
            "user": ThemeTone("white", attrs=("bold",)),
            "assistant": ThemeTone("cyan"),
            "stream": ThemeTone("magenta"),
            "tool": ThemeTone("yellow", attrs=("bold",)),
            "result": ThemeTone("green"),
            "input": ThemeTone("white", attrs=("bold",)),
            "system": ThemeTone("red"),
        },
    ),
}


def list_theme_names() -> list[str]:
    return list(THEMES.keys())


def normalize_theme(name: str | None) -> str:
    candidate = str(name or "").strip().lower()
    if candidate in THEMES:
        return candidate
    return DEFAULT_THEME


def get_theme(name: str | None) -> ThemeSpec:
    return THEMES[normalize_theme(name)]


def describe_palette(theme: ThemeSpec) -> str:
    sample_roles = ["hero", "chrome", "user", "assistant", "tool", "result", "input"]
    return ", ".join(f"{role}={theme.palette[role].label()}" for role in sample_roles)


def build_theme_preview_text(name: str | None, *, width: int = 88) -> str:
    theme = get_theme(name)
    separator = theme.separator * max(24, min(width, 64))
    return "\n".join(
        [
            "Theme Preview",
            "=============",
            f"name: {theme.label} ({theme.name})",
            f"palette: {describe_palette(theme)}",
            separator,
            f"operator > Review the authorized scope before scanning.",
            f"ares     > Ready. Streaming analysis with the {theme.label} palette.",
            f"tool     > split_targets {{\"targets\": \"corp.example;vpn.example\"}}",
            f"result   > {{\"targets\": [\"corp.example\", \"vpn.example\"]}}",
            f"status   > theme preview active",
            f"{theme.prompt_prefix}/theme preview {theme.name}",
        ]
    )
