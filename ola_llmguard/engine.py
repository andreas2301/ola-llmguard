import threading
from abc import ABC, abstractmethod

from llm_guard.input_scanners import Anonymize
from llm_guard.input_scanners.anonymize_helpers import DEBERTA_AI4PRIVACY_v2_CONF
from llm_guard.output_scanners import Deanonymize
from llm_guard.vault import Vault


class PiiEngine(ABC):
    """Injectable interface for a PII scanner/redactor.

    Tests use a deterministic fake implementation; production wires the real
    llm-guard scanner via :class:`LlmGuardEngine`.
    """

    @abstractmethod
    def anonymize(self, text: str) -> tuple[str, dict]:
        """Return redacted text plus a {placeholder: original} mapping."""
        ...

    @abstractmethod
    def deanonymize(self, text: str, mapping: dict) -> str:
        """Restore placeholders in ``text`` using ``mapping``."""
        ...


class LlmGuardEngine(PiiEngine):
    """REAL PII engine backed by Protect AI's llm-guard Anonymize scanner.

    Loads the Isotonic/deberta-v3-base_finetuned_ai4privacy_v2 model once via
    llm-guard's ``DEBERTA_AI4PRIVACY_v2_CONF`` with ONNX acceleration. The
    heavy transformer/presidio analyzer is built exactly once; the per-request
    ``Vault()`` is swapped under a lock so mappings do not leak across requests.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Build the scanner once. The vault passed here is only a placeholder;
        # we replace ``_vault`` with a fresh ``Vault()`` on each ``anonymize()``
        # call. This is the documented per-request-isolation mechanism for
        # llm-guard 0.3.16 (there is no public per-request vault API), so the
        # version is pinned in requirements.txt. The lock serializes the swap.
        self._scanner = Anonymize(
            Vault(),
            recognizer_conf=DEBERTA_AI4PRIVACY_v2_CONF,
            use_onnx=True,
        )

    def anonymize(self, text: str) -> tuple[str, dict]:
        with self._lock:
            # Fresh vault for this request; the loaded model stays cached.
            vault = Vault()
            self._scanner._vault = vault
            redacted, _, _ = self._scanner.scan(text)
            mapping = dict(vault.get())
        return redacted, mapping

    def deanonymize(self, text: str, mapping: dict) -> str:
        vault = Vault(list(mapping.items()))
        scanner = Deanonymize(vault)
        restored, _, _ = scanner.scan("", text)
        return restored
