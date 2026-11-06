"""ホスト単位の簡易レート制限。

プロセス内の記録だけを見る。再起動で消える。窓を過ぎた記録は捨てる。
"""

from __future__ import annotations

import threading
import time
from collections import deque

WINDOW = 60.0
LIMIT = 5

_hits: dict[str, deque] = {}
_lock = threading.Lock()


def hit(key: str, *, now: float | None = None, limit: int = LIMIT, window: float = WINDOW) -> bool:
    """1回分を記録する。上限に達していれば False。"""
    current = time.monotonic() if now is None else now
    with _lock:
        queue = _hits.setdefault(key, deque())
        while queue and current - queue[0] >= window:
            queue.popleft()
        if len(queue) >= limit:
            return False
        queue.append(current)
        return True


def reset() -> None:
    with _lock:
        _hits.clear()