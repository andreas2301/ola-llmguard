from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from ola_gateway_shared.transport import caller_cn_dependency

from .engine import PiiEngine
from .store import TokenStore


class _AnonymizeRequest(BaseModel):
    prompt: str


class _DeanonymizeRequest(BaseModel):
    token: str
    text: str


class _DiscardRequest(BaseModel):
    token: str


def create_app(
    engine: PiiEngine,
    allowed_cns: frozenset[str] = frozenset(),
) -> FastAPI:
    app = FastAPI()
    store = TokenStore()

    app.state.allowed_cns = allowed_cns
    app.state.caller_cn_dep = caller_cn_dependency
    caller_dep = Depends(app.state.caller_cn_dep)

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/anonymize")
    async def anonymize(req: _AnonymizeRequest, caller_cn: str = caller_dep) -> dict:
        try:
            redacted, mapping = engine.anonymize(req.prompt)
        except Exception:
            # Fail closed: block the request and never echo the raw prompt.
            raise HTTPException(status_code=500, detail="anonymization failed") from None

        token = store.issue(caller_cn, mapping)
        return {"redacted": redacted, "token": token}

    @app.post("/deanonymize")
    async def deanonymize(req: _DeanonymizeRequest, caller_cn: str = caller_dep) -> dict:
        mapping = store.consume(req.token, caller_cn)
        if mapping is None:
            # No leak of whether the token existed or who owned it.
            raise HTTPException(status_code=404, detail="invalid or expired token")

        try:
            restored = engine.deanonymize(req.text, mapping)
        except Exception:
            # Fail closed: never echo the redacted text or the mapping.
            raise HTTPException(status_code=500, detail="deanonymization failed") from None

        return {"restored": restored}

    @app.post("/discard")
    async def discard(req: _DiscardRequest, caller_cn: str = caller_dep) -> dict:
        store.discard(req.token, caller_cn)
        return {"status": "ok"}

    return app
