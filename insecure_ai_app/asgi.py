"""ASGI entry point: `uvicorn insecure_ai_app.asgi:app --reload --port 8000`."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import api, db, rag, tools

app = FastAPI(
    title="insecure-ai-app",
    description="Intentionally vulnerable LLM/agent test target.",
    docs_url="/api/docs",
)

# Reflects any origin and allows credentials: the agent API is callable from
# any page the victim visits.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api.router)


@app.on_event("startup")
def startup() -> None:
    db.initialize()
    rag.initialize()
    rag.initialize_web()
    tools.load_manifest()
