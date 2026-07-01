"""Batch/conversation anonymize — one shared Vault so placeholders are coherent
across all texts, one token for the whole request. This is the primitive that lets
the Oracle gateway redact an entire conversation (all messages) instead of only the
last user message, so enforced callers can safely route to a remote provider.

The token stays single-use + caller-bound (store.py unchanged); the existing
/deanonymize and /discard already work with a batch token.
"""
import pytest
from fastapi.testclient import TestClient

from ola_llmguard.app import create_app
from ola_llmguard.engine import LlmGuardEngine, PiiEngine

_ALLOWED = "client.example.internal"


class _FakeBatchEngine(PiiEngine):
    """Deterministic fake: assigns each known name a stable placeholder using a SHARED
    counter across all texts in a batch (mirrors the real shared-Vault behaviour), so
    the same entity gets the same placeholder in every text and two entities never
    collide onto one placeholder."""

    _NAMES = ("Alice", "Bob", "Carol")

    def anonymize(self, text: str):
        red, mapping = self._redact([text])
        return red[0], mapping

    def deanonymize(self, text: str, mapping: dict) -> str:
        for ph, orig in mapping.items():
            text = text.replace(ph, orig)
        return text

    def anonymize_batch(self, texts):
        return self._redact(list(texts))

    def _redact(self, texts):
        assigned = {}  # original -> placeholder, shared across ALL texts
        out = []
        for t in texts:
            for name in self._NAMES:
                if name in t and name not in assigned:
                    assigned[name] = f"[REDACTED_{len(assigned)}]"
            for name, ph in assigned.items():
                t = t.replace(name, ph)
            out.append(t)
        mapping = {ph: name for name, ph in assigned.items()}
        return out, mapping


def _client(engine=None, caller=_ALLOWED):
    app = create_app(engine=engine or _FakeBatchEngine())
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: caller
    return app, TestClient(app)


def test_batch_redacts_every_text_and_returns_one_token():
    _, c = _client()
    r = c.post("/anonymize_batch", json={"texts": ["I am Alice", "Bob emailed Alice", "no names here"]})
    assert r.status_code == 200
    body = r.json()
    assert len(body["redacted"]) == 3
    assert "Alice" not in body["redacted"][0]
    assert "Alice" not in body["redacted"][1] and "Bob" not in body["redacted"][1]
    assert body["redacted"][2] == "no names here"
    assert isinstance(body["token"], str) and len(body["token"]) >= 32


def test_batch_placeholders_are_coherent_across_texts():
    """The same entity MUST map to the same placeholder in every text, and two entities
    must never share a placeholder (the collision the shared Vault prevents)."""
    _, c = _client()
    body = c.post("/anonymize_batch", json={"texts": ["Alice", "Alice and Bob"]}).json()
    alice_ph = body["redacted"][0]                       # "[REDACTED_0]"
    assert alice_ph in body["redacted"][1]               # same placeholder for Alice in text 1
    # Bob got a DIFFERENT placeholder (no collision)
    assert body["redacted"][1] != f"{alice_ph} and {alice_ph}"


def test_batch_roundtrip_restores_all_entities():
    _, c = _client()
    body = c.post("/anonymize_batch", json={"texts": ["Alice met Bob"]}).json()
    tok, redacted = body["token"], body["redacted"][0]
    # a provider "response" that echoes both placeholders restores to both originals
    restored = c.post("/deanonymize", json={"token": tok, "text": f"reply: {redacted}"}).json()["restored"]
    assert "Alice" in restored and "Bob" in restored


def test_batch_token_is_caller_bound():
    app, c = _client(caller=_ALLOWED)
    tok = c.post("/anonymize_batch", json={"texts": ["I am Alice"]}).json()["token"]
    # a different verified caller must NOT be able to deanonymize the batch token
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: "attacker.example"
    r = c.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r.status_code == 404


def test_batch_empty_list_is_ok():
    _, c = _client()
    r = c.post("/anonymize_batch", json={"texts": []})
    assert r.status_code == 200
    assert r.json()["redacted"] == []


@pytest.mark.slow
def test_batch_real_engine_coherence_and_roundtrip():
    """Real-model coherence check: the same entity must share one placeholder across
    all texts in the batch, and a deanonymize round-trip must restore it."""
    engine = LlmGuardEngine()
    redacted, mapping = engine.anonymize_batch(
        ["My name is Alice Smith.", "Email Alice Smith at a@b.com"]
    )
    # Find the placeholder that maps back to "Alice Smith".
    alice_placeholders = [ph for ph, orig in mapping.items() if orig == "Alice Smith"]
    assert len(alice_placeholders) == 1, f"expected one placeholder for Alice Smith, got {mapping}"
    alice_ph = alice_placeholders[0]
    assert alice_ph in redacted[0]
    assert alice_ph in redacted[1]
    # Deanonymize round-trip restores the shared placeholder in both texts.
    restored = engine.deanonymize(f"reply: {redacted[0]} / {redacted[1]}", mapping)
    assert "Alice Smith" in restored
