"""Deploy tests — uvicorn exact-pin + token-store TTL eviction."""
import pathlib
import re
import time


def test_uvicorn_exact_pinned_in_requirements():
    """uvicorn is a hard import (main.py/transport.py) + the Docker CMD; a clean airgapped
    build fails without it in requirements. It must be EXACT-pinned (the CN-pin rides uvicorn
    internals; a float can silently degrade to blanket-401)."""
    req = (pathlib.Path(__file__).resolve().parent.parent / "requirements.txt").read_text().splitlines()
    assert any(re.match(r"uvicorn==\S+", l.strip()) for l in req), \
        "uvicorn must be exact-pinned (uvicorn==X.Y.Z) in requirements.txt"


def test_store_evicts_expired_on_consume():
    """Expired plaintext-PII mappings must be swept on consume() (not only on issue()), or they
    linger in RAM under idle traffic past the TTL."""
    from ola_llmguard.store import TokenStore
    s = TokenStore(ttl_seconds=0.01)
    tok = s.issue("client.example.internal", {"[REDACTED_0]": "SECRET1"})
    time.sleep(0.02)
    s.consume("some-other-unknown-token", "client.example.internal")  # a miss must still sweep
    assert tok not in s._tokens, "expired token's plaintext mapping must be evicted on consume()"
