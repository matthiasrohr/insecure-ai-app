# AGENTS.md

Working rules for coding agents in this repository.

## Purpose

`insecure-ai-app` is an intentionally vulnerable local LangGraph/FastAPI target
for validating scanners and threat-modeling tools against **LLM and agentic**
security problems. It is not an implementation example.

It should help a tool distinguish:

- confirmed exploitable vulnerabilities
- implementation weaknesses without a direct attacker path
- design weaknesses without a concrete exploit instance
- clean counter-examples that should not be reported

## Do not harden

Do not remove or secure planted weaknesses unless the user explicitly asks.

In particular, do not accidentally:

- add a trust boundary between the system prompt, user input, retrieved
  documents, tool results or tool descriptions in `llm.py` / `graph.py`
- stop concatenating retrieved text into the `system` channel (`retrieve_node`)
- remove the indirect-injection payload in `rag.SEED_DOCUMENTS` (`kb-102`) or the
  poisoned `lookup_order` description in `tools.DEFAULT_MANIFEST`
- add authentication, review or sanitization to `POST /api/rag/documents`,
  `POST /api/mcp/tools`, or the memory tools
- turn on `ENFORCE_TENANT_ISOLATION`, `ENABLE_OUTPUT_FILTER`, or
  `REQUIRE_TOOL_APPROVAL` (or make `approved` server-controlled)
- add allowlists / normalization / confirmation to `run_shell`, `read_file`,
  `http_get`, `sql_query`, `send_email`, or `calc`
- add an owner/thread ownership check to `graph.get_thread` / `read_thread`
- replace `pickle` in `graph.load_state`
- stop taking `user_id` / `thread_id` from the request body
- HTML-escape model output in `chat.html` or `api.debug_echo`
- tighten the reflected-origin CORS middleware
- move the hardcoded secrets out of `config.py` or the system prompt
- add signature/pinning/provenance checks to `tools.install_plugin`
- add grounding, citation or "I don't know" behavior to the main agent, or
  validate `rag.web_search` results as anything but fact
- add rate limiting or a token/cost budget to `/api/agent/batch` or `/api/chat`
- add message signing/validation between the coordinator and worker in
  `multiagent.py`, or restrict the worker's tool surface
- turn on `ENABLE_AUDIT_LOG`, `ENABLE_RATE_LIMIT`, `VERIFY_PLUGIN_SIGNATURES`,
  or set `TRUST_PEER_AGENT_MESSAGES = False`

Do NOT harden the `/api/guarded/*` routes or `insecure_ai_app/guarded.py` in the
other direction either — they are the clean counter-examples and must stay safe.

UI polish is fine if it does not change security semantics.

## Keep documentation in sync

For substantive test-case changes, review `README.md`, `EXPECTED-FINDINGS.md`,
and `AGENTS.md`. Document the finding classification, affected location,
endpoint, and a short PoC.

## Build and verification

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
.venv/bin/uvicorn insecure_ai_app.asgi:app --reload --port 8000
```

`tests/test_smoke.py` asserts that the planted weaknesses still work and that
the counter-examples stay safe. A failing test means a fixture regressed.
