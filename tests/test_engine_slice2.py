"""Integration test — the REAL PII engine (llm-guard, deberta-v3-ai4privacy + ONNX).

Pins the reversible redact→restore round-trip on genuine PII using `LlmGuardEngine` (in place of
the injectable fake engine). Slow (loads the transformer model); that is expected for an
integration test. Offline vendoring (SHA-pinned model + Dockerfile + TRANSFORMERS_OFFLINE) is
verified separately by the build, not this unit test.
"""
import pytest

pytestmark = pytest.mark.slow


def test_llmguard_engine_redacts_and_restores_pii():
    from ola_llmguard.engine import LlmGuardEngine

    eng = LlmGuardEngine()
    text = "Please email John Doe at john.doe@example.com about invoice 12345."
    redacted, mapping = eng.anonymize(text)

    # PII is gone from what would leave to the provider
    assert "john.doe@example.com" not in redacted
    assert mapping, "reversible placeholder map must be non-empty"

    # and is reversibly restored for the caller
    restored = eng.deanonymize(redacted, mapping)
    assert "john.doe@example.com" in restored


def test_llmguard_engine_conforms_to_pii_engine_interface():
    from ola_llmguard.engine import LlmGuardEngine, PiiEngine

    eng = LlmGuardEngine()
    assert isinstance(eng, PiiEngine) or hasattr(eng, "anonymize") and hasattr(eng, "deanonymize")
    red, m = eng.anonymize("no pii here")
    assert isinstance(red, str) and isinstance(m, (dict, list))
