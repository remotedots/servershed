"""Development helpers (not used at runtime)."""
from __future__ import annotations

from watchfiles import Change, DefaultFilter


class CodeFilter(DefaultFilter):
    """Restart only for code: .py and .sh. app.tcss is excluded on purpose,
    `servershed --dev` already reloads it live without a restart."""

    extensions = (".py", ".sh")

    def __call__(self, change: Change, path: str) -> bool:
        return path.endswith(self.extensions) and super().__call__(change, path)
