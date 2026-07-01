import secrets
import threading
import time
from typing import Optional


class TokenStore:
    """Thread-safe, single-use token store with TTL and a max-entry cap.

    Each token is a server-generated CSPRNG value bound to a verified caller CN and
    a {placeholder: original} mapping. Tokens are invalidated on consume and expire
    after ``ttl_seconds`` if never consumed.
    """

    def __init__(
        self,
        ttl_seconds: float = 600.0,
        max_entries: int = 10000,
    ) -> None:
        self._lock = threading.Lock()
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        # token -> (caller_cn, mapping, issued_at_monotonic)
        self._tokens: dict[str, tuple[str, dict, float]] = {}

    def _evict(self, now: float) -> None:
        """Remove expired entries and, if over the cap, the oldest entries."""
        # Evict expired entries first.
        expired = [
            token
            for token, (_, _, issued_at) in self._tokens.items()
            if now - issued_at > self._ttl
        ]
        for token in expired:
            entry = self._tokens.pop(token)
            entry[1].clear()

        # If still over the cap, evict oldest entries (dict preserves insertion order).
        while len(self._tokens) > self._max_entries:
            oldest_token = next(iter(self._tokens))
            entry = self._tokens.pop(oldest_token)
            entry[1].clear()

    def issue(self, caller_cn: str, mapping: dict) -> str:
        """Generate a fresh token bound to ``caller_cn`` and ``mapping``."""
        token = secrets.token_hex(16)  # 128-bit, 32 hex chars
        with self._lock:
            self._tokens[token] = (caller_cn, mapping, time.monotonic())
            self._evict(time.monotonic())
        return token

    def consume(self, token: str, caller_cn: str) -> Optional[dict]:
        """Return the mapping if ``token`` exists and belongs to ``caller_cn``, else None.

        The token is invalidated (single-use) on a successful consume. Expired
        tokens are treated as absent and removed.
        """
        with self._lock:
            self._evict(time.monotonic())
            entry = self._tokens.get(token)
            if entry is None:
                return None
            stored_cn, mapping, issued_at = entry
            if time.monotonic() - issued_at > self._ttl:
                del self._tokens[token]
                mapping.clear()
                return None
            if stored_cn != caller_cn:
                return None
            del self._tokens[token]
            return mapping

    def discard(self, token: str, caller_cn: str) -> None:
        """Purge ``token`` if it exists and belongs to ``caller_cn``."""
        with self._lock:
            self._evict(time.monotonic())
            entry = self._tokens.get(token)
            if entry is not None and entry[0] == caller_cn:
                mapping = self._tokens.pop(token)[1]
                mapping.clear()
