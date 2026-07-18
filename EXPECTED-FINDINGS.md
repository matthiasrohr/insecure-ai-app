# Expected Findings

This file is the authoritative map of intentional findings for `insecure-ai-app`.
Source code should not be hardened unless the test case is intentionally changed.

Classifications:

- **CONFIRMED-EXPLOITABLE** — a concrete attacker path exists and is reproducible.
- **IMPLEMENTATION-WEAKNESS** — an unsafe primitive without a direct end-to-end exploit in the demo.
- **DESIGN-WEAKNESS** — a missing control at the architecture level (no exploit instance on its own).
- **STANDARD-VETTED counter-example** — intentionally safe; a scanner should NOT report it.

A counter-example demonstrates **one specific control** (a tenant filter, an owner
check, an egress allowlist). It is not a hardened application: no route in this app
is authenticated, so any control keyed to a caller-supplied `user_id` scopes without
enforcing. Rows below state per case what is and is not demonstrated. Where a control
turned out to be bypassable it has been reclassified as a finding.

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
| T10 | Overwhelming Human-in-the-Loop | yes (approval gate is inert in every configuration) |
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
| STANDARD-VETTED counter-example | `api.guarded_ask`, `guarded.guarded_answer` | `GET /api/guarded/ask` | Safe, but **not** by the mechanism the fencing helpers suggest: `guarded_answer` never invokes a model, so there is no injection surface to defend. `guarded.wrap_untrusted` and `guarded.GUARDED_SYSTEM_PROMPT` are defined but unreferenced (dead code) — do not treat this endpoint as a working demonstration of prompt-level fencing. The fence would also be escapable if wired up: the closing tag is stripped in a single non-recursive pass, so `</untrusted_docu</untrusted_document>ment>` collapses into a valid terminator. |

## LLM02 — Sensitive Information Disclosure

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `api.system_prompt` | `GET /api/system-prompt` | System prompt with embedded keys served unauthenticated. |
| CONFIRMED-EXPLOITABLE | `api.app_config` | `GET /api/config` | Internal API key, DB password and Stripe key returned in JSON. |
| IMPLEMENTATION-WEAKNESS | `config.INTERNAL_API_KEY`, `config.DB_PASSWORD`, `config.STRIPE_KEY`, `config.SESSION_SIGNING_KEY` | N/A | Hardcoded secrets. |
| DESIGN-WEAKNESS | `config.SYSTEM_PROMPT` | N/A | Secrets carried in-band in the prompt, so any injection leaks them. |
| IMPLEMENTATION-WEAKNESS | `db.initialize` (`users.ssn`, `api_keys.token`) | `POST /api/tools/invoke` | SSNs and a live-format admin token (`acme-live-admin-ROOT-9931`) stored in plaintext, reachable via `sql_query` and via `lookup_order` (see LLM06). |
| STANDARD-VETTED counter-example | `guarded.redact` | `GET /api/guarded/ask` | Output filter strips key/SSN patterns before returning. **Partial denylist, not a complete control:** it covers `INTERNAL_API_KEY` and `STRIPE_KEY`, but `DB_PASSWORD`, `SESSION_SIGNING_KEY` and the seeded DB tokens pass through unchanged. No end-to-end leak on the guarded path today, since only document text reaches it. |

## LLM03 — Supply Chain

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `tools.install_plugin`, `api.install_plugin` | `POST /api/plugins/install` | A tool manifest is fetched from a caller-supplied URL and trusted: no signature, no pinning, no provenance. Its descriptions then reach the model. |
| CONFIRMED-EXPLOITABLE | `tools.REGISTRY` (`install_plugin`), `tools.DEFAULT_MANIFEST`, `graph._tool_catalog` | `POST /api/chat` | `install_plugin` is also registered as an *agent* tool and advertised in the manifest, so an injection can make the model install an attacker manifest itself. The new descriptions are reloaded into the tool catalog on every later turn, for every user: self-inflicted, persistent tool poisoning that outlives the session. |
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
| CONFIRMED-EXPLOITABLE | `tools.lookup_order` | `POST /api/tools/invoke`, agent tool | Distinct from the text-to-SQL sink above: a fixed, developer-written query with the parameter interpolated (`f"... WHERE id = {order_id}"`). Classic SQL injection (`1 OR 1=1 --`, `UNION SELECT` against `api_keys`), plus no owner check, so any order of any tenant is readable. |
| CONFIRMED-EXPLOITABLE | `tools.send_email` | agent tool | Exfiltration sink: no recipient allowlist, no confirmation. |
| CONFIRMED-EXPLOITABLE | `graph.approve_node`, `api.chat` (`approved`) | `POST /api/chat` | Human-in-the-loop gate is inert: **all three branches return `approved: True`**. With `REQUIRE_TOOL_APPROVAL=true` and `approved=false` it still proceeds and only appends a system note, and no graph edge halts before `tools_node`. The config switch is decorative — do not read the enabled state as a working control. |
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
| STANDARD-VETTED counter-example | `guarded.retrieve_for_tenant` | `GET /api/guarded/ask` | Retrieval is filtered by `d.tenant == tenant`, which is the control being demonstrated. **It scopes but does not authenticate:** the tenant is derived from an unauthenticated `user_id` query parameter, so `?user_id=103` retrieves as globex and returns the `kb-200` acquisition memo. Read this row as "the filter is applied", not as tenant isolation. Same caveat for `GET /api/guarded/grounded`. |

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
| IMPLEMENTATION-WEAKNESS | `rag.index_document`, `rag.remember`, `rag.publish_web_page` | `POST /api/rag/documents`, `POST /api/web/pages`, `POST /api/chat` | A second consumption axis: unauthenticated writes append to unbounded in-memory lists with no size or count cap, and `rag.search` scans them linearly on every agent turn, so retrieval cost grows with the number of injected documents. |
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
| STANDARD-VETTED counter-example | `guarded.audit`, `api.guarded_audit_log` | `GET /api/guarded/audit-log` | An append-only, readable audit log exists and is written to. **Coverage is one endpoint only:** `api.guarded_grounded` calls `audit()`; `guarded/ask`, `guarded/fetch`, `guarded/orders` and `guarded/batch` record nothing. |

## Agentic — Memory, Identity and State

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `graph.get_thread`, `api.read_thread` | `GET /api/threads/{id}` | IDOR on agent conversations: any thread readable by id. |
| CONFIRMED-EXPLOITABLE | `graph.run` (`thread_id`), `api.chat` | `POST /api/chat` | Checkpoints keyed by caller-chosen `thread_id`; no ownership check (session hijack / poisoning). |
| CONFIRMED-EXPLOITABLE | `graph.dump_state`, `api.export_state` | `GET /api/agent/state/{thread_id}` | The export half: any thread's pickled agent state is returned base64-encoded, unauthenticated. Exfiltrates other users' conversation state, and hands the attacker a valid pickle to tamper with and feed back to the import route below. |
| CONFIRMED-EXPLOITABLE | `graph.load_state`, `api.import_state` | `POST /api/agent/state/load` | Insecure deserialization of caller-supplied pickled agent state (RCE). |
| CONFIRMED-EXPLOITABLE | `api.chat` (`user_id`) | `POST /api/chat` | Identity taken from the request body; caller impersonates any seeded user. |
| CONFIRMED-EXPLOITABLE | `api.my_orders` | `GET /api/orders/mine` | Despite its "Parameterized and owner-scoped" docstring there is **no owner check at all**: `user_id` is an unauthenticated query parameter, so `?user_id=103` returns another tenant's orders. Same IDOR class the `api.chat` (`user_id`) row already confirms. |
| STANDARD-VETTED counter-example | `guarded.guarded_orders`, `db.safe_orders_for_user` | `GET /api/guarded/orders` | Parameterized query plus an explicit owner check — those two controls are real and are what this row demonstrates. **The check is tautological**, because `user_id` and `owner_id` both come from the same anonymous caller (`?user_id=102&owner_id=102` succeeds). It shows the shape of an owner check, not enforced access control. |

## Web and Transport Policy

| Expected classification | Location | Endpoint | Notes |
| --- | --- | --- | --- |
| CONFIRMED-EXPLOITABLE | `asgi.CORSMiddleware` | N/A | Reflects any origin and allows credentials. |
| DESIGN-WEAKNESS | `asgi.app` | N/A | No authentication, rate limiting, or CSRF protection on any route. |
| CONFIRMED-EXPLOITABLE | `guarded.guarded_fetch`, `api.guarded_fetch` | `GET /api/guarded/fetch` | **Intended as a counter-example, but the host allowlist is bypassable — treat it as an SSRF finding, not as vetted.** Parser differential: the guard reads the host with `urlparse().hostname`, the request is issued by `requests`/`urllib3`, and the two disagree on a backslash in the authority. For `https://evil.example\@docs.acme.example/`, `urlparse` yields `docs.acme.example` (allowed) while `urllib3` connects to `evil.example`. The HTTPS-only check and `allow_redirects=False` do hold; the host check does not. |
