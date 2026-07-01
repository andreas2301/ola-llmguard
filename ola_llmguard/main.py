"""Production ASGI entrypoint for the ola-llmguard sidecar.

Wires the real llm-guard PII engine into the FastAPI app and serves it over mTLS
using the shared ``ola-gateway-shared`` helpers. The listener requires a client
certificate; the application layer then enforces the pinned peer-CN allowlist via
:func:`ola_gateway_shared.transport.resolve_caller_cn` and
:func:`ola_gateway_shared.tls.peer_cn_allowed`.

The set of authorized client CNs is supplied at deploy time via the
``GATEWAY_ALLOWED_CNS`` environment variable (comma-separated). An empty allowlist
denies every caller (fail-closed); :func:`run` refuses to start with one.
"""
import os

import uvicorn
from ola_gateway_shared.tls import new_ssl_context

from ola_llmguard.app import create_app
from ola_llmguard.engine import LlmGuardEngine
from ola_gateway_shared.transport import PeerCertProtocol

ALLOWED_CNS = frozenset(
    cn.strip()
    for cn in os.environ.get("GATEWAY_ALLOWED_CNS", "").split(",")
    if cn.strip()
)


def build_app(engine=None):
    """Construct the production FastAPI app with the real PII engine."""
    if engine is None:
        engine = LlmGuardEngine()
    return create_app(engine, allowed_cns=ALLOWED_CNS)


def run() -> None:
    """Serve the sidecar over mutual TLS using the shared mTLS helpers."""
    assert uvicorn.__version__ == "0.49.0", (
        "ola-llmguard pins uvicorn 0.49.0: the mTLS peer-CN injection "
        "(PeerCertProtocol) depends on its H11Protocol scope internals + "
        "ssl_context_factory; re-verify on bump"
    )
    if not ALLOWED_CNS:
        raise RuntimeError(
            "GATEWAY_ALLOWED_CNS must list at least one authorized client CN "
            "(comma-separated); refusing to start with an empty allowlist"
        )
    app = build_app()

    cert_file = os.environ.get("GATEWAY_TLS_CERT_FILE")
    key_file = os.environ.get("GATEWAY_TLS_KEY_FILE")
    ca_file = os.environ.get("GATEWAY_TLS_CA_FILE")

    ssl_context = new_ssl_context(
        role="server",
        cert_file=cert_file,
        key_file=key_file,
        ca_file=ca_file,
    )

    host = os.environ.get("GATEWAY_HOST", "127.0.0.1")
    port = int(os.environ.get("GATEWAY_PORT", "8443"))

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        http=PeerCertProtocol,
        ssl_context_factory=lambda _config, _default_factory: ssl_context,
    )
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    run()
