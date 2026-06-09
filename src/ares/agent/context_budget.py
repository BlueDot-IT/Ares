from __future__ import annotations


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class ContextBudgeter:
    def __init__(self, max_tokens: int) -> None:
        self.max_tokens = max_tokens
        self.used_tokens = 0
        self.sections: list[str] = []

    def remaining(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    def add_section(self, title: str, body: str, *, priority: int = 50) -> bool:
        body = body.strip()
        if not body:
            return False
        text = f"{title}\n{body}".strip()
        cost = estimate_tokens(text)
        if cost > self.remaining():
            trimmed = self._trim_to_remaining(text)
            if not trimmed:
                return False
            text = trimmed
            cost = estimate_tokens(text)
        self.sections.append(text)
        self.used_tokens += cost
        return True

    def render(self) -> str:
        return "\n\n".join(self.sections).strip()

    def _trim_to_remaining(self, text: str) -> str:
        remaining_chars = self.remaining() * 4
        if remaining_chars < 200:
            return ""
        return text[:remaining_chars].rstrip() + "\n[truncated by context budget]"
