"""Transport tests — mTLS server-side peer-CN allowlist.

The engine server must accept ONLY the pinned client CN (client.example.internal) at the app
layer (TLS verifies the chain, not the CN). Derivation from the verified peer cert + enforcement
is pure and unit-tested here; the uvicorn/mTLS wiring lives in main.py and must go through the
shared ``ola_gateway_shared`` helpers (new_ssl_context / PeerCertProtocol), never an inline ssl
context.
"""
import importlib
import inspect

import pytest
from fastapi import HTTPException


def test_resolve_caller_cn_allows_pinned_cn():
    from ola_gateway_shared.transport import resolve_caller_cn
    peercert = {"subject": ((("commonName", "client.example.internal"),),)}
    assert resolve_caller_cn(peercert, {"client.example.internal"}) == "client.example.internal"


def test_resolve_caller_cn_rejects_unlisted_cn_403():
    from ola_gateway_shared.transport import resolve_caller_cn
    peercert = {"subject": ((("commonName", "other.example.internal"),),)}
    with pytest.raises(HTTPException) as e:
        resolve_caller_cn(peercert, {"client.example.internal"})
    assert e.value.status_code == 403


def test_resolve_caller_cn_rejects_no_peer_cert_401():
    from ola_gateway_shared.transport import resolve_caller_cn
    with pytest.raises(HTTPException) as e:
        resolve_caller_cn(None, {"client.example.internal"})
    assert e.value.status_code == 401


def test_resolve_caller_cn_no_substring_bypass():
    from ola_gateway_shared.transport import resolve_caller_cn
    # a substring of the allowed CN must NOT satisfy the allowlist
    peercert = {"subject": ((("commonName", "lient.example.interna"),),)}
    with pytest.raises(HTTPException):
        resolve_caller_cn(peercert, {"client.example.internal"})


def test_main_pins_cn_from_env_and_uses_shared_mtls(monkeypatch):
    """main.py derives its CN allowlist from GATEWAY_ALLOWED_CNS and builds the server
    TLS context via the shared helper (never an inline ssl context)."""
    monkeypatch.setenv("GATEWAY_ALLOWED_CNS", "client.example.internal, other.example.internal")
    from ola_llmguard import main
    importlib.reload(main)
    try:
        assert "client.example.internal" in main.ALLOWED_CNS
        assert "other.example.internal" in main.ALLOWED_CNS
        src = inspect.getsource(main)
        assert "new_ssl_context" in src          # shared TLS helper, not inline ssl.SSLContext
        assert "PeerCertProtocol" in src          # shared peer-cert scope injection
    finally:
        monkeypatch.delenv("GATEWAY_ALLOWED_CNS", raising=False)
        importlib.reload(main)


def test_main_refuses_empty_allowlist():
    """An unset/empty GATEWAY_ALLOWED_CNS must fail-closed: run() refuses to start."""
    from ola_llmguard import main
    # import-time default (no env) is an empty, deny-all allowlist
    assert main.ALLOWED_CNS == frozenset()
    with pytest.raises(RuntimeError):
        main.run()
