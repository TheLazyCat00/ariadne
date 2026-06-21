"""Small helpers shared by the native and IL frontends."""
from __future__ import annotations

import glob


def hr(title: str) -> None:
    """Print a section header banner."""
    print("\n" + "=" * 66 + "\n  " + title + "\n" + "=" * 66)


def read_file_prefix(path: str, n: int = 16 * 1024 * 1024) -> bytes:
    """Read up to the first `n` bytes of `path`, or b"" on any error."""
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def glob_limited(pattern: str, limit: int = 24) -> list[str]:
    """glob.glob(pattern) capped at `limit` matches, never raising."""
    out: list[str] = []
    try:
        for x in glob.glob(pattern):
            out.append(x)
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out
