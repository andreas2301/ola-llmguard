"""Batch deanonymize — restore a LIST of texts with ONE single-use, caller-bound
token in ONE call. Symmetric with /anonymize_batch: the Oracle gateway can restore a
provider response's content PLUS every tool-call argument in a single round-trip,
retiring the fragile sentinel-join it uses today.

The token stays single-use + caller-bound (store.py unchanged): the WHOLE batch
consumes the token exactly once, so a second /deanonymize_batch — or a follow-up
/deanonymize — with the same token must 404.
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
    collide onto one placeholder. deanonymize is a plain reverse substitution; the
    batch variant is the concrete default inherited from PiiEngine."""

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


def test_deanonymize_batch_restores_all_parts_from_one_token():
    """Round-trip an /anonymize_batch token through /deanonymize_batch: a provider
    'response' content plus a tool-call arg, restored in one call."""
    _, c = _client()
    body = c.post("/anonymize_batch", json={"texts": ["Alice met Bob"]}).json()
    tok, redacted = body["token"], body["redacted"][0]
    # Simulate the two things the gateway restores together: response content + a
    # tool-call argument, each echoing placeholders from the shared batch mapping.
    r = c.post(
        "/deanonymize_batch",
        json={"token": tok, "texts": [f"reply: {redacted}", f"arg={redacted}"]},
    )
    assert r.status_code == 200
    restored = r.json()["restored"]
    assert len(restored) == 2
    assert "Alice" in restored[0] and "Bob" in restored[0]
    assert "Alice" in restored[1] and "Bob" in restored[1]


def test_deanonymize_batch_is_single_use_second_batch_call_404s():
    _, c = _client()
    body = c.post("/anonymize_batch", json={"texts": ["I am Alice", "Bob too"]}).json()
    tok = body["token"]
    first = c.post("/deanonymize_batch", json={"token": tok, "texts": ["[REDACTED_0]"]})
    assert first.status_code == 200
    # The batch already consumed the token; a second batch call must 404.
    second = c.post("/deanonymize_batch", json={"token": tok, "texts": ["[REDACTED_0]"]})
    assert second.status_code == 404


def test_deanonymize_batch_consumes_token_for_single_deanonymize_too():
    """SINGLE-USE across endpoints: after the batch consumes the token, a follow-up
    single /deanonymize with the same token must 404."""
    _, c = _client()
    tok = c.post("/anonymize_batch", json={"texts": ["I am Alice"]}).json()["token"]
    assert c.post("/deanonymize_batch", json={"token": tok, "texts": ["[REDACTED_0]"]}).status_code == 200
    r = c.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r.status_code == 404


def test_deanonymize_batch_is_caller_bound():
    app, c = _client(caller=_ALLOWED)
    tok = c.post("/anonymize_batch", json={"texts": ["I am Alice"]}).json()["token"]
    # A DIFFERENT verified caller must not be able to consume the batch token.
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: "attacker.example"
    r = c.post("/deanonymize_batch", json={"token": tok, "texts": ["[REDACTED_0]"]})
    assert r.status_code == 404


def test_deanonymize_batch_preserves_length_and_order():
    _, c = _client()
    body = c.post("/anonymize_batch", json={"texts": ["Alice", "Bob", "Carol"]}).json()
    tok, red = body["token"], body["redacted"]
    # Distinct placeholders in a deliberately shuffled order; the restore must map
    # position-for-position, not re-sort.
    inputs = [red[2], red[0], red[1]]  # Carol, Alice, Bob
    restored = c.post("/deanonymize_batch", json={"token": tok, "texts": inputs}).json()["restored"]
    assert restored == ["Carol", "Alice", "Bob"]


def test_deanonymize_batch_empty_list_returns_empty_and_consumes_token():
    _, c = _client()
    tok = c.post("/anonymize_batch", json={"texts": ["I am Alice"]}).json()["token"]
    r = c.post("/deanonymize_batch", json={"token": tok, "texts": []})
    assert r.status_code == 200
    assert r.json()["restored"] == []
    # The empty batch still consumed the token → any reuse now 404s.
    reuse = c.post("/deanonymize_batch", json={"token": tok, "texts": []})
    assert reuse.status_code == 404


@pytest.mark.slow
def test_deanonymize_batch_real_engine_roundtrip():
    """Real-model round-trip through the HTTP layer: anonymize_batch two texts sharing
    an entity, then deanonymize_batch BOTH redacted texts with the single returned
    token → both originals restored coherently. Uses the real DeBERTa engine; if it is
    unavailable this test errors (we never fake the model)."""
    engine = LlmGuardEngine()
    app = create_app(engine=engine)
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: _ALLOWED
    c = TestClient(app)

    body = c.post(
        "/anonymize_batch",
        json={"texts": ["Alice met Bob", "Bob emailed Alice"]},
    ).json()
    tok, redacted = body["token"], body["redacted"]
    assert len(redacted) == 2

    restored = c.post(
        "/deanonymize_batch",
        json={"token": tok, "texts": redacted},
    ).json()["restored"]
    assert len(restored) == 2
    # Both names must reappear across the restored batch (shared placeholder namespace).
    joined = " ".join(restored)
    assert "Alice" in joined and "Bob" in joined
    # Order preserved: text 0 was "Alice met Bob", text 1 was "Bob emailed Alice".
    assert "Alice" in restored[0] and "Bob" in restored[0]
    assert "Bob" in restored[1] and "Alice" in restored[1]
