"""Tests — ola-llmguard PII sidecar core (no heavy ML models).

Pins the security-critical anonymize/deanonymize/discard orchestration, with the actual PII
scanner behind an injectable interface (real llm-guard wiring + offline model vendoring are
covered by the integration tests). Contract under test:

  POST /anonymize   {prompt}            -> 200 {redacted, token}      token = server-gen >=128-bit, caller-bound
  POST /deanonymize {token, text}       -> 200 {restored}            token must exist + belong to THIS caller
  POST /discard     {token}             -> 200                       purge; subsequent deanonymize fails
  GET  /healthz                         -> 200 (no client cert)

Invariants: token is server-generated CSPRNG (never caller-supplied); bound to the verified caller
identity (peer-cert CN), not a body field; reuse/unknown/cross-caller deanonymize rejected; engine
error => fail-closed (request BLOCKED, nothing leaked); plaintext PII held only in the per-token map,
discarded on /discard.
"""
import re
import time

import pytest
from fastapi.testclient import TestClient

from ola_llmguard.app import create_app
from ola_llmguard.engine import PiiEngine
from ola_llmguard.store import TokenStore


class FakeEngine(PiiEngine):
    """Deterministic stand-in for llm-guard: redacts 'SECRET<n>' tokens reversibly."""

    def anonymize(self, text: str):
        mapping = {}
        out = text
        for i, m in enumerate(sorted(set(re.findall(r"SECRET\d+", text)))):
            ph = f"[REDACTED_{i}]"
            mapping[ph] = m
            out = out.replace(m, ph)
        return out, mapping

    def deanonymize(self, text: str, mapping: dict):
        for ph, original in mapping.items():
            text = text.replace(ph, original)
        return text


def _client(engine=None, caller="client.example.internal"):
    """App with caller identity injected (prod derives it from the verified mTLS peer cert)."""
    app = create_app(engine=engine or FakeEngine())
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: caller
    return TestClient(app)


def test_healthz_no_client_cert():
    c = _client()
    assert c.get("/healthz").status_code == 200


def test_anonymize_returns_redacted_and_csprng_token():
    c = _client()
    r = c.post("/anonymize", json={"prompt": "call SECRET1 and SECRET2 now"})
    assert r.status_code == 200
    body = r.json()
    assert body["redacted"] == "call [REDACTED_0] and [REDACTED_1] now"
    assert "SECRET1" not in body["redacted"] and "SECRET2" not in body["redacted"]
    tok = body["token"]
    assert re.fullmatch(r"[0-9a-f]{32,}", tok)  # >=128-bit hex, server-generated
    # caller cannot supply/choose the token
    r2 = c.post("/anonymize", json={"prompt": "x", "token": "attacker-chosen"})
    assert r2.json()["token"] != "attacker-chosen"


def test_deanonymize_restores_only_with_valid_token():
    c = _client()
    tok = c.post("/anonymize", json={"prompt": "SECRET1"}).json()["token"]
    r = c.post("/deanonymize", json={"token": tok, "text": "result [REDACTED_0] done"})
    assert r.status_code == 200
    assert r.json()["restored"] == "result SECRET1 done"


def test_deanonymize_unknown_token_rejected():
    c = _client()
    r = c.post("/deanonymize", json={"token": "00deadbeef" * 4, "text": "[REDACTED_0]"})
    assert r.status_code in (400, 403, 404)
    assert "SECRET" not in r.text


def test_token_single_use_then_reuse_rejected():
    c = _client()
    tok = c.post("/anonymize", json={"prompt": "SECRET1"}).json()["token"]
    assert c.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"}).status_code == 200
    # a token is consumed by deanonymize (or by discard); a second deanonymize must fail
    r2 = c.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r2.status_code in (400, 403, 404)


def test_token_bound_to_caller_no_cross_caller_restore():
    # ONE app / ONE store, two callers — so the rejection is the CALLER-BINDING check,
    # not store/instance isolation (two _client()s would each have a separate store and
    # pass even if the CN check were removed — mutation-verified).
    app = create_app(engine=FakeEngine())
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: "client.example.internal"
    client = TestClient(app)
    tok = client.post("/anonymize", json={"prompt": "SECRET1"}).json()["token"]
    # switch the VERIFIED caller on the same app/store
    app.dependency_overrides[app.state.caller_cn_dep] = lambda: "other.example.internal"
    r = client.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r.status_code in (400, 403, 404)
    assert "SECRET1" not in r.text


def test_discard_purges_map():
    c = _client()
    tok = c.post("/anonymize", json={"prompt": "SECRET1"}).json()["token"]
    assert c.post("/discard", json={"token": tok}).status_code == 200
    r = c.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r.status_code in (400, 403, 404)


def test_fail_closed_on_engine_error():
    class Boom(PiiEngine):
        def anonymize(self, text):
            raise RuntimeError("scanner down")

        def deanonymize(self, text, mapping):
            raise RuntimeError("scanner down")

    c = _client(engine=Boom())
    r = c.post("/anonymize", json={"prompt": "SECRET1"})
    assert r.status_code >= 500          # BLOCKED, fail-closed
    assert "SECRET1" not in r.text       # no leak of the raw prompt in the error


def test_engine_error_does_not_leak_pii_in_response_or_logs(caplog):
    """A fail-closed engine exception must not echo PII in the response body or logs."""
    pii = "SECRET-PII-12345"

    class Boom(PiiEngine):
        def anonymize(self, text):
            raise RuntimeError(f"scanner exploded on {pii}")

        def deanonymize(self, text, mapping):
            raise RuntimeError(f"scanner exploded on {pii}")

    caplog.set_level("ERROR")
    c = _client(engine=Boom())

    r = c.post("/anonymize", json={"prompt": pii})
    assert r.status_code == 500
    assert pii not in r.text
    assert pii not in caplog.text

    # Deanonymize path must also hide the mapping/redacted text on engine failure.
    class DeanonymizeBoom(PiiEngine):
        def anonymize(self, text):
            return "[REDACTED_0]", {"[REDACTED_0]": "SECRET1"}

        def deanonymize(self, text, mapping):
            raise RuntimeError(f"deanonymizer exploded on {pii}")

    c2 = _client(engine=DeanonymizeBoom())
    tok = c2.post("/anonymize", json={"prompt": "SECRET1"}).json()["token"]
    r2 = c2.post("/deanonymize", json={"token": tok, "text": "[REDACTED_0]"})
    assert r2.status_code == 500
    assert "SECRET1" not in r2.text
    assert pii not in r2.text


def test_token_expires_after_ttl():
    store = TokenStore(ttl_seconds=0.01)
    token = store.issue("client.example.internal", {"[REDACTED_0]": "SECRET1"})
    assert store.consume(token, "client.example.internal") == {"[REDACTED_0]": "SECRET1"}

    token2 = store.issue("client.example.internal", {"[REDACTED_1]": "SECRET2"})
    time.sleep(0.02)
    assert store.consume(token2, "client.example.internal") is None


def test_store_size_bounded():
    store = TokenStore(ttl_seconds=60.0, max_entries=10)
    for i in range(20):
        store.issue("client.example.internal", {f"[REDACTED_{i}]": f"SECRET{i}"})
    assert len(store._tokens) <= 10
