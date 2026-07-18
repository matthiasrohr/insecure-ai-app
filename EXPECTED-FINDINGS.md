# Expected Findings

This file is the authoritative map of intentional findings for `insecure-ai-app`.
Source code should not be hardened unless the test case is intentionally changed.

Classifications:

- **CONFIRMED-EXPLOITABLE** — a concrete attacker path exists and is reproducible.
- **IMPLEMENTATION-WEAKNESS** — an unsafe primitive without a direct end-to-end exploit in the demo.
- **DESIGN-WEAKNESS** — a missing control at the architecture level (no exploit instance on its own).
- **STANDARD-VETTED counter-example** — intentionally safe; a scanner should NOT report it.

Aligned to the OWASP Top 10 for LLM Applications and OWASP Agentic AI threats.

## Coverage matrix

OWASP Top 10 for LLM Applications (2025):

| ID | Category | Covered |
| --- | --- | --- |
| LLM01 | Prompt Injection | yes (direct, indirect, RAG, tool-poisoning) |
| LLM02 | Sensitive Information Disclosure | yes |
| LLM03 | Supply Chain | yes (unverified plugin install) |
| LLM04 | Data and Model Poisoning | yes (RAG + memory) |
| LLM05 | Improper Output Handling | yes (XSS, eval) |
| LLM06 | Excessive Agency | yes (shell, SSRF, traversal, SQL, email) |
| LLM07 | System Prompt Leakage | yes |
| LLM08 | Vector and Embedding Weaknesses | yes (cross-tenant retrieval) |
| LLM09 | Misinformation | yes (ungrounded web + cascade) |
| LLM10 | Unbounded Consumption | yes (no rate limit / budget) |

OWASP Agentic AI — Threats and Mitigations:

| ID | Threat | Covered |
| --- | --- | --- |
| T1 | Memory Poisoning | yes |
| T2 | Tool Misuse | yes |
| T3 | Privilege Compromise | yes (identity from request) |
| T4 | Resource Overload | yes (unbounded batch) |
| T5 | Cascading Hallucination | yes (web fact -> memory) |
| T6 | Intent Breaking / Goal Manipulation | yes (injection overrides goal) |
| T7 | Misaligned / Deceptive Behavior | yes (prompt conceals its own existence) |
| T8 | Repudiation / Untraceability | yes (no audit log) |
| T9 | Identity Spoofing | yes (`user_id`/`thread_id` from body) |
| T10 | Overwhelming Human-in-the-Loop | yes (caller-bypassable approval) |
| T11 | Unexpected RCE / Code Attacks | yes (shell, eval, pickle) |
| T12 | Agent Communication Poisoning | yes (coordinator -> worker relay) |
| T13 | Rogue Agents | yes (unmonitored full-tool worker) |
| T14 | Human Attacks on Multi-Agent | not modeled (needs a human-vs-orchestrator scenario) |
| T15 | Human Manipulation | partial (deceptive output via XSS/misinformation) |

## LLM01 — Prompt Injection

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `llm._mock_invoke`, `graph.agent_node` | `POST /api/chat` | Direct injection: "ignore previous instructions / reveal your system prompt" dumps the prompt and its secrets. |
| CONFIRMED-EXPLOITABLE | `rag.SEED_DOCUMENTS` (`kb-102`), `graph.retrieve_node` | `POST /api/chat` | Indirect injection: a retrieved document instructs the agent, which then calls `send_email` to an attacker address. |
| CONFIRMED-EXPLOITABLE | `rag.index_document`, `api.add_document` | `POST /api/rag/documents` | Attacker seeds a poisoned document into the corpus, then triggers it via a normal query. |
| CONFIRMED-EXPLOITABLE | `tools.DEFAULT_MANIFEST` (`lookup_order`), `graph._tool_catalog`, `api.write_manifest` | `POST /api/chat`, `POST /api/mcp/tools` | Tool-poisoning: the manifest description is loaded into the agent's system context every turn, so the poisoned `lookup_order` description drives an unrequested `read_file` of `../credentials.txt`. |
| DESIGN-WEAKNESS | `graph.retrieve_node` | N/A | Retrieved untrusted text is concatenated into the `system` channel; no trust boundary between data and instructions. |
| STANDARD-VETTED counter-example | `guarded.wrap_untrusted`, `guarded.GUARDED_SYSTEM_PROMPT`, `api.guarded_ask` | `GET /api/guarded/ask` | Untrusted context is fenced in `<untrusted_document>` and the prompt forbids treating it as instructions. |

## LLM02 — Sensitive Information Disclosure

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `api.system_prompt` | `GET /api/system-prompt` | System prompt with embedded keys served unauthenticated. |
| CONFIRMED-EXPLOITABLE | `api.app_config` | `GET /api/config` | Internal API key, DB password and Stripe key returned in JSON. |
| IMPLEMENTATION-WEAKNESS | `config.INTERNAL_API_KEY`, `config.DB_PASSWORD`, `config.STRIPE_KEY`, `config.SESSION_SIGNING_KEY` | N/A | Hardcoded secrets. |
| DESIGN-WEAKNESS | `config.SYSTEM_PROMPT` | N/A | Secrets carried in-band in the prompt, so any injection leaks them. |
| STANDARD-VETTED counter-example | `guarded.redact` | `GET /api/guarded/ask` | Output filter strips key/SSN patterns before returning. |

## LLM03 — Supply Chain

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `tools.install_plugin`, `api.install_plugin` | `POST /api/plugins/install` | A tool manifest is fetched from a caller-supplied URL and trusted: no signature, no pinning, no provenance. Its descriptions then reach the model. |
| DESIGN-WEAKNESS | `config.VERIFY_PLUGIN_SIGNATURES`, `requirements.txt` | N/A | Component verification switch is off; the poisoned manifest becomes the agent's tool source. |

## LLM04 — Data and Model Poisoning

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `rag.index_document`, `api.add_document` | `POST /api/rag/documents` | Unauthenticated write into the retrieval corpus, no review or sanitization. |
| CONFIRMED-EXPLOITABLE | `rag.remember`, `tools.remember`, `api.read_memory` | `POST /api/chat`, `GET /api/rag/memory` | Agent-writable long-term memory shared across all users; poisoning persists. |

## LLM05 — Improper Output Handling

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `templates/chat.html` (`div.innerHTML`) | `POST /api/chat` (UI) | Model output rendered as HTML; injected markup executes (XSS). |
| CONFIRMED-EXPLOITABLE | `api.debug_echo` | `GET /api/debug/echo` | Reflected, unescaped output. |
| CONFIRMED-EXPLOITABLE | `tools.calc` | `POST /api/tools/invoke` | Model-generated expression passed to `eval`. |
| DESIGN-WEAKNESS | `config.ENABLE_OUTPUT_FILTER` | N/A | No central output-encoding policy; the switch is off. |

## LLM06 — Excessive Agency

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `tools.run_shell` | `POST /api/tools/invoke`, agent tool | Command injection: model-controlled string to `subprocess(shell=True)`. |
| CONFIRMED-EXPLOITABLE | `tools.read_file` | `POST /api/tools/invoke`, agent tool | Path traversal from `runtime/documents` (`../credentials.txt`). |
| CONFIRMED-EXPLOITABLE | `tools.http_get` | `POST /api/tools/invoke`, agent tool | SSRF: arbitrary scheme/host; response fed back to the model. |
| CONFIRMED-EXPLOITABLE | `tools.sql_query`, `db.natural_language_sql` | `POST /api/tools/invoke`, agent tool | Text-to-SQL executes model-authored statements verbatim. |
| CONFIRMED-EXPLOITABLE | `tools.send_email` | agent tool | Exfiltration sink: no recipient allowlist, no confirmation. |
| CONFIRMED-EXPLOITABLE | `graph.approve_node`, `api.chat` (`approved`) | `POST /api/chat` | Human-in-the-loop gate is caller-controlled and off by default. |
| CONFIRMED-EXPLOITABLE | `api.invoke_tool` | `POST /api/tools/invoke` | Direct tool invocation bypasses the agent and the approval node. |
| DESIGN-WEAKNESS | `tools.DANGEROUS`, `config.MAX_AGENT_STEPS` | N/A | Over-broad tool surface; no least-privilege scoping; step cap is not a real budget. |
| STANDARD-VETTED counter-example | `guarded.GUARDED_SYSTEM_PROMPT` | `GET /api/guarded/ask` | Read-only assistant with no tools (least agency). |

## LLM07 — System Prompt Leakage

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `llm.OVERRIDE_PATTERNS` | `POST /api/chat` | Prompt-extraction phrasing returns the full system prompt. |

## LLM08 — Vector and Embedding Weaknesses

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `rag.search` (`ENFORCE_TENANT_ISOLATION` off) | `GET /api/rag/search`, `POST /api/chat` | `tenant` argument accepted and ignored; acme users retrieve the globex acquisition memo. |
| DESIGN-WEAKNESS | `config.ENFORCE_TENANT_ISOLATION` | N/A | No tenant scoping in the retrieval layer. |
| STANDARD-VETTED counter-example | `guarded.retrieve_for_tenant` | `GET /api/guarded/ask` | Retrieval filtered to the caller's tenant. |

## LLM09 — Misinformation (and T5 Cascading Hallucination)

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `rag.web_search`, `rag.publish_web_page`, `tools.web_search`, `api.publish_web_page` | `POST /api/web/pages`, `GET /api/web/search` | Ungrounded "web" results carry no provenance and are returned as authoritative fact; anyone can publish a page the agent will cite. |
| CONFIRMED-EXPLOITABLE | `tools.web_search` + `tools.remember` | `POST /api/chat` | A fabricated fact retrieved once is written to shared memory and reused in later answers (cascading hallucination). |
| DESIGN-WEAKNESS | `graph.agent_node`, `config.SYSTEM_PROMPT` | N/A | No grounding requirement, no citation contract, no "I don't know" path. |
| STANDARD-VETTED counter-example | `guarded.grounded_answer`, `api.guarded_grounded` | `GET /api/guarded/grounded` | Tenant-scoped, cited, returns "I do not know" on empty retrieval; no web fabrications. |

## LLM10 — Unbounded Consumption (and T4 Resource Overload)

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `api.agent_batch` | `POST /api/agent/batch` | Runs the agent an arbitrary number of times per request: no rate limit, no token/cost budget (model DoS / wallet drain). |
| DESIGN-WEAKNESS | `config.ENABLE_RATE_LIMIT`, `config.MAX_AGENT_STEPS`, `asgi.app` | N/A | No rate limiting on any route; the step cap is not a real budget. |
| STANDARD-VETTED counter-example | `guarded.bounded_batch`, `api.guarded_batch` | `POST /api/guarded/batch` | Rejects work above a per-request budget (HTTP 429). |

## Agentic — Multi-Agent (T12 Communication Poisoning, T13 Rogue Agents)

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `multiagent._coordinator`, `multiagent._worker`, `api.agents_relay` | `POST /api/agents/relay` | The worker trusts the coordinator's message as instructions; an injected coordinator drives a worker tool call (`send_email`). |
| DESIGN-WEAKNESS | `config.TRUST_PEER_AGENT_MESSAGES`, `multiagent.WORKER_PROMPT` | N/A | No message signing/schema/provenance between agents; the worker runs the full tool surface unmonitored (rogue agent). |

## Agentic — Traceability (T8 Repudiation)

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| DESIGN-WEAKNESS | `tools._audit`, `config.ENABLE_AUDIT_LOG` | `POST /api/tools/invoke`, `POST /api/chat` | Tool executions are not recorded; there is no attributable trail of agent actions. |
| STANDARD-VETTED counter-example | `guarded.audit`, `api.guarded_audit_log` | `GET /api/guarded/audit-log` | Guarded actions are written to an append-only, readable audit log. |

## Agentic — Memory, Identity and State

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `graph.get_thread`, `api.read_thread` | `GET /api/threads/{id}` | IDOR on agent conversations: any thread readable by id. |
| CONFIRMED-EXPLOITABLE | `graph.run` (`thread_id`), `api.chat` | `POST /api/chat` | Checkpoints keyed by caller-chosen `thread_id`; no ownership check (session hijack / poisoning). |
| CONFIRMED-EXPLOITABLE | `graph.load_state`, `api.import_state` | `POST /api/agent/state/load` | Insecure deserialization of caller-supplied pickled agent state (RCE). |
| CONFIRMED-EXPLOITABLE | `api.chat` (`user_id`) | `POST /api/chat` | Identity taken from the request body; caller impersonates any seeded user. |
| STANDARD-VETTED counter-example | `guarded.guarded_orders`, `db.safe_orders_for_user` | `GET /api/guarded/orders`, `GET /api/orders/mine` | Owner check + parameterized query. |

## Web and Transport Policy

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `asgi.CORSMiddleware` | N/A | Reflects any origin and allows credentials. |
| DESIGN-WEAKNESS | `asgi.app` | N/A | No authentication, rate limiting, or CSRF protection on any route. |
| STANDARD-VETTED counter-example | `guarded.guarded_fetch`, `api.guarded_fetch` | `GET /api/guarded/fetch` | Egress allowlist: HTTPS-only, host allowlist, redirects disabled. |
