"""mTLS INTEGRATION test — proves the peer-CN control actually runs.

The unit tests override the caller dependency, so the real cert-reading path would otherwise have
ZERO coverage. This boots the app over a REAL mTLS listener (uvicorn + the shared new_ssl_context
server context + the custom protocol that injects the peer cert into the scope) and drives it with
genuine client certs: the allowed CN -> 200, a valid-chain non-allowed CN -> 403, no client cert ->
TLS handshake refused. Slow (real server + handshake); uses a fake engine so no model load.
"""
import datetime
import ipaddress
import socket
import ssl
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = pytest.mark.slow

_NVB = datetime.datetime(2020, 1, 1)
_NVA = datetime.datetime(2035, 1, 1)


def _ca():
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "itest-ca")])
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(_NVB).not_valid_after(_NVA)
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(k, hashes.SHA256()))
    return k, c


def _leaf(ca_k, ca_c, cn, san=None):
    k = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(ca_c.subject).public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(_NVB).not_valid_after(_NVA)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    c = builder.sign(ca_k, hashes.SHA256())
    return (c.public_bytes(serialization.Encoding.PEM),
            k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))


@pytest.fixture(scope="module")
def mtls_server(tmp_path_factory):
    d = tmp_path_factory.mktemp("mtls")
    ca_k, ca_c = _ca()
    ca_p = d / "ca.pem"; ca_p.write_bytes(ca_c.public_bytes(serialization.Encoding.PEM))
    srv_cert, srv_key = _leaf(
        ca_k, ca_c, "llmguard.example.internal",
        san=[x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))],
    )
    (d / "cert.pem").write_bytes(srv_cert); (d / "key.pem").write_bytes(srv_key)

    # build the app with a FakeEngine (no model) + the oracle CN pin, served via the shared helper
    from ola_llmguard.app import create_app
    from tests.test_sidecar_slice1 import FakeEngine
    from ola_gateway_shared.tls import new_ssl_context
    from ola_gateway_shared.transport import PeerCertProtocol  # the custom protocol that injects peercert into scope

    app = create_app(engine=FakeEngine(), allowed_cns=frozenset({"client.example.internal"}))
    ctx = new_ssl_context(role="server", cert_file=str(d / "cert.pem"), key_file=str(d / "key.pem"), ca_file=str(ca_p))

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, http=PeerCertProtocol,
                            ssl_context_factory=lambda *a: ctx, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True); t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "mTLS server did not start"

    def client(cn=None):
        # Build a single SSL context for the client: trust the test CA, present
        # the requested client cert, and verify the server's IP SAN.
        ctx = ssl.create_default_context(cafile=str(ca_p))
        if cn is not None:
            cert_pem, key_pem = _leaf(ca_k, ca_c, cn)
            cp = d / f"{cn}.cert"; kp = d / f"{cn}.key"
            cp.write_bytes(cert_pem); kp.write_bytes(key_pem)
            ctx.load_cert_chain(str(cp), str(kp))
        return httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=ctx)

    yield client
    server.should_exit = True
    t.join(timeout=5)


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def test_oracle_cn_allowed_200(mtls_server):
    with mtls_server("client.example.internal") as c:
        r = c.post("/anonymize", json={"prompt": "SECRET1"})
        assert r.status_code == 200
        assert "token" in r.json()


def test_nonoracle_cn_forbidden_403(mtls_server):
    with mtls_server("other.example.internal") as c:
        r = c.post("/anonymize", json={"prompt": "SECRET1"})
        assert r.status_code == 403


def test_no_client_cert_handshake_refused(mtls_server):
    with mtls_server(None) as c:
        with pytest.raises((httpx.ConnectError, ssl.SSLError, httpx.TransportError)):
            c.post("/anonymize", json={"prompt": "SECRET1"})
