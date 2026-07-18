"""FastAPI surface.

Every route is unauthenticated. `user_id` is taken from the request, so the
caller states who they are and the server believes it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import config, db, graph, guarded, multiagent, rag, tools

router = APIRouter()

TEMPLATES = Path(__file__).resolve().parent / "templates"


def _user(user_id: int) -> dict:
    user = config.SEED_USERS.get(int(user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="unknown user")
    return {"id": int(user_id), **user}


# --- UI ----------------------------------------------------------------------


@router.get("/", response_class=HTMLResponse)
def chat_ui() -> str:
    return (TEMPLATES / "chat.html").read_text(encoding="utf-8")


# --- Agent -------------------------------------------------------------------


@router.post("/api/chat")
def chat(payload: dict = Body(...)) -> dict:
    """Main agent entry point.

    No authentication, no rate limit, no token budget, and both `thread_id` and
    `approved` are attacker-controlled.
    """
    message = payload.get("message", "")
    thread_id = payload.get("thread_id", "default")
    user = _user(payload.get("user_id", 100))
    approved = bool(payload.get("approved", False))

    state = graph.run(message, thread_id=thread_id, user=user, approved=approved)
    messages = state.get("messages", [])
    reply = ""
    for msg in reversed(messages):
        if msg.type == "ai" and msg.content:
            reply = msg.content
            break
    return {
        "reply": reply,
        "thread_id": thread_id,
        "trace": [
            {"type": m.type, "content": m.content, "tool_calls": getattr(m, "tool_calls", None)}
            for m in messages
        ],
    }


@router.get("/api/threads/{thread_id}")
def read_thread(thread_id: str) -> dict:
    """Any conversation is readable by id."""
    return {"thread_id": thread_id, "messages": graph.get_thread(thread_id)}


@router.get("/api/agent/state/{thread_id}")
def export_state(thread_id: str) -> dict:
    return {"state": base64.b64encode(graph.dump_state(thread_id)).decode()}


@router.post("/api/agent/state/load")
def import_state(payload: dict = Body(...)) -> dict:
    """Caller-supplied pickle is deserialized."""
    blob = base64.b64decode(payload.get("state", ""))
    restored = graph.load_state(blob)
    return {"restored_keys": list(restored) if hasattr(restored, "__iter__") else str(restored)}


# --- Tools -------------------------------------------------------------------


@router.get("/api/mcp/tools")
def list_tools() -> dict:
    """Tool manifest, including attacker-writable descriptions."""
    return tools.load_manifest()


@router.post("/api/mcp/tools")
def write_manifest(payload: dict = Body(...)) -> dict:
    """Anyone can rewrite the tool descriptions the model reads."""
    tools.MCP_MANIFEST.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"status": "written"}


@router.post("/api/tools/invoke")
def invoke_tool(payload: dict = Body(...)) -> dict:
    """Direct tool invocation, bypassing the agent and the approval node entirely."""
    return {"result": tools.execute(payload.get("name", ""), payload.get("args") or {})}


# --- Knowledge base ----------------------------------------------------------


@router.post("/api/rag/documents")
def add_document(payload: dict = Body(...)) -> dict:
    """Unauthenticated write into the retrieval corpus."""
    doc = rag.index_document(
        title=payload.get("title", "untitled"),
        content=payload.get("content", ""),
        tenant=payload.get("tenant", "acme"),
    )
    return {"doc_id": doc.doc_id, "tenant": doc.tenant}


@router.get("/api/rag/search")
def search_documents(q: str, tenant: str = "acme") -> dict:
    """`tenant` is accepted and ignored: retrieval crosses tenant boundaries."""
    docs = rag.search(q, tenant=tenant)
    return {
        "results": [
            {"doc_id": d.doc_id, "tenant": d.tenant, "title": d.title, "content": d.content}
            for d in docs
        ]
    }


@router.get("/api/rag/memory")
def read_memory() -> dict:
    return {"memory": rag.recall()}


# --- LLM09 / T5: ungrounded "web" corpus -------------------------------------


@router.post("/api/web/pages")
def publish_web_page(payload: dict = Body(...)) -> dict:
    """Anyone can publish a page the agent later cites as authoritative fact."""
    page = rag.publish_web_page(payload.get("title", "untitled"), payload.get("content", ""))
    return {"page_id": page.doc_id}


@router.get("/api/web/search")
def web_search(q: str) -> dict:
    pages = rag.web_search(q)
    return {"results": [{"title": p.title, "content": p.content} for p in pages]}


# --- LLM03: supply chain -----------------------------------------------------


@router.post("/api/plugins/install")
def install_plugin(payload: dict = Body(...)) -> dict:
    """Install a third-party tool manifest from a URL with no provenance check."""
    return {"result": tools.install_plugin(url=payload.get("url", ""))}


# --- LLM10 / T4: unbounded consumption ---------------------------------------


@router.post("/api/agent/batch")
def agent_batch(payload: dict = Body(...)) -> dict:
    """Run the agent an arbitrary number of times. No rate limit, no budget."""
    count = int(payload.get("count", 1))  # unbounded on purpose
    message = payload.get("message", "")
    replies = []
    for i in range(count):
        state = graph.run(message, thread_id=f"batch-{i}", user=_user(100))
        replies.append(next((m.content for m in reversed(state["messages"]) if m.type == "ai"), ""))
    return {"runs": count, "replies": replies}


# --- T12 / T13: multi-agent relay --------------------------------------------


@router.post("/api/agents/relay")
def agents_relay(payload: dict = Body(...)) -> dict:
    """Coordinator -> worker. The worker trusts the peer message as instructions."""
    query = payload.get("message", "")
    docs = rag.search(query)
    context = "\n\n".join(f"{d.title}: {d.content}" for d in docs)
    return multiagent.relay(query, context=context)


# --- Disclosure --------------------------------------------------------------


@router.get("/api/system-prompt", response_class=PlainTextResponse)
def system_prompt() -> str:
    """The system prompt, secrets included, served to anyone who asks."""
    return config.SYSTEM_PROMPT


@router.get("/api/config")
def app_config() -> dict:
    return {
        "provider": config.LLM_PROVIDER,
        "model": config.ANTHROPIC_MODEL,
        "internal_api_key": config.INTERNAL_API_KEY,
        "db_password": config.DB_PASSWORD,
        "stripe_key": config.STRIPE_KEY,
        "require_tool_approval": config.REQUIRE_TOOL_APPROVAL,
    }


@router.get("/api/debug/echo", response_class=HTMLResponse)
def debug_echo(text: str) -> str:
    """Reflected, unescaped: the model's or the caller's markup is rendered."""
    return f"<html><body><h3>echo</h3><div>{text}</div></body></html>"


# --- Guarded counter-examples (should NOT be reported) -----------------------


@router.get("/api/guarded/ask")
def guarded_ask(q: str, user_id: int) -> dict:
    user = _user(user_id)
    return {"answer": guarded.guarded_answer(q, tenant=user["tenant"])}


@router.get("/api/guarded/fetch")
def guarded_fetch(url: str) -> dict:
    try:
        return {"body": guarded.guarded_fetch(url)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/api/guarded/orders")
def guarded_orders(user_id: int, owner_id: int) -> dict:
    try:
        return {"orders": guarded.guarded_orders(int(user_id), int(owner_id))}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@router.get("/api/guarded/grounded")
def guarded_grounded(q: str, user_id: int) -> dict:
    """LLM09 counter-example: tenant-scoped, cited, 'I do not know' on empty."""
    user = _user(user_id)
    result = guarded.grounded_answer(q, tenant=user["tenant"])
    guarded.audit(actor=user["name"], action="grounded_ask", detail=q)
    return result


@router.post("/api/guarded/batch")
def guarded_batch(payload: dict = Body(...)) -> dict:
    """LLM10 counter-example: per-request budget is enforced."""
    try:
        count = guarded.bounded_batch(int(payload.get("count", 1)))
    except ValueError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return {"allowed_runs": count}


@router.get("/api/guarded/audit-log", response_class=PlainTextResponse)
def guarded_audit_log() -> str:
    """T8 counter-example: guarded actions are recorded and readable."""
    if guarded.GUARDED_AUDIT_PATH.exists():
        return guarded.GUARDED_AUDIT_PATH.read_text(encoding="utf-8")
    return ""


@router.get("/api/guarded/whoami")
def guarded_whoami(request: Request) -> dict:
    return {"client": request.client.host if request.client else None}


@router.get("/api/orders/mine")
def my_orders(user_id: int) -> dict:
    """Parameterized and owner-scoped."""
    return {"orders": db.safe_orders_for_user(int(user_id))}
