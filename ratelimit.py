import time
from collections import defaultdict, deque

from fastapi import HTTPException

_hits = defaultdict(deque)


def check_rate(key: str, limit: int, window_seconds: int) -> None:
    """Allow at most `limit` calls per `window_seconds` for this key."""
    now = time.monotonic()
    q = _hits[key]
    while q and now - q[0] > window_seconds:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a moment and try again.",
        )
    q.append(now)