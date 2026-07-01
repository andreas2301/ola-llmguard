#!/usr/bin/env bash
# Offline model vendoring script for ola-llmguard.
# Downloads the ai4privacy DeBERTa ONNX model (via HuggingFace) and the
# spaCy models Presidio/llm-guard needs into ./vendored-models/ so the
# air-gapped Docker build can run without outbound network access.
set -euo pipefail

VENDOR_DIR="./vendored-models"
HF_CACHE_DIR="${VENDOR_DIR}/hf-cache/hub"
SPACY_DIR="${VENDOR_DIR}/spacy"
SHA_FILE="./models.sha256"

# Pin the exact HuggingFace model revision so the vendored artifact is reproducible.
MODEL_REVISION="9ea992753ab2686be4a8f64605ccc7be197ad794"

mkdir -p "${HF_CACHE_DIR}" "${SPACY_DIR}"

# DeBERTa-v3 ai4privacy v2 ONNX model (Isotonic/deberta-v3-base_finetuned_ai4privacy_v2).
# Tokenizer + config JSON files are included alongside the onnx/ subfolder so
# optimum+transformers can load the model entirely from the vendored HF cache in
# offline mode.
echo "Vendoring Isotonic/deberta-v3-base_finetuned_ai4privacy_v2 (ONNX, rev ${MODEL_REVISION})..."
.venv/bin/huggingface-cli download \
    Isotonic/deberta-v3-base_finetuned_ai4privacy_v2 \
    --revision "${MODEL_REVISION}" \
    --cache-dir "${HF_CACHE_DIR}" \
    --local-dir-use-symlinks False \
    --include "onnx/*" \
    --include "config.json" \
    --include "*.json" \
    --include "tokenizer*" \
    --include "spm.model" \
    --include "added_tokens.json" \
    --include "special_tokens_map.json"

# spaCy small models required by llm-guard's Presidio analyzer.
# Pin to 3.8.x to match the spacy version pulled in by llm-guard.
SPACY_VERSION="3.8.0"
for model in en_core_web_sm zh_core_web_sm; do
    echo "Vendoring ${model}..."
    curl -fsSL -o "${SPACY_DIR}/${model}-${SPACY_VERSION}-py3-none-any.whl" \
        "https://github.com/explosion/spacy-models/releases/download/${model}-${SPACY_VERSION}/${model}-${SPACY_VERSION}-py3-none-any.whl"
done

# Record SHA-256 checksums of every vendored artifact.
echo "Writing ${SHA_FILE}..."
find "${VENDOR_DIR}" -type f -print0 | sort -z | xargs -0 sha256sum > "${SHA_FILE}"

echo "Vendoring complete. Artifacts in ${VENDOR_DIR}, checksums in ${SHA_FILE}."