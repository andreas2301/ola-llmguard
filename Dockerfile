FROM python:3.12-slim

# Disable all runtime network access to model hubs / telemetry.
ENV TRANSFORMERS_OFFLINE=1 \
    HF_HUB_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1 \
    DO_NOT_TRACK=1 \
    # Point transformers/optimum at the vendored HuggingFace cache.
    HF_HOME=/app/vendored-models/hf-cache \
    GATEWAY_HOST=0.0.0.0 \
    GATEWAY_PORT=8443

WORKDIR /app

# Install Python dependencies from exact pins.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Install the shared ola-gateway-shared mTLS helpers from a vendored wheel so
# ola_gateway_shared.tls / .transport (new_ssl_context, peer_cn_allowed,
# PeerCertProtocol) are importable inside the image. The deployment supplies the
# exact built wheel; do not fetch it from a package index.
COPY wheels/ /app/wheels/
RUN pip install --no-cache-dir /app/wheels/ola_gateway_shared-*.whl

# Copy vendored models (DeBERTa ONNX + spaCy models) and checksums.
COPY vendored-models/ /app/vendored-models/
COPY models.sha256 /app/models.sha256

# Verify vendored model integrity before the build continues.
RUN cd /app && sha256sum -c models.sha256

# Install spaCy models from vendored wheels so Presidio/llm-guard never phones home.
RUN pip install --no-cache-dir --no-index --find-links /app/vendored-models/spacy \
    en_core_web_sm zh_core_web_sm

# Copy application source.
COPY ola_llmguard/ /app/ola_llmguard/

# Build-stage smoke: ensure the package imports cleanly before committing the image.
RUN python -c 'import ola_llmguard.main'

# Run as a non-root user. uid 15100 is a dedicated, collision-free id (uid 1000 collides
# with agent-routine/n8n on the host, and the :ro /certs mount is chowned to this uid —
# a shared uid would let another service read this engine's key.pem on the host).
RUN useradd -m -u 15100 llmguard && chown -R llmguard:llmguard /app
USER llmguard

EXPOSE 8443

CMD ["python", "-m", "ola_llmguard.main"]
