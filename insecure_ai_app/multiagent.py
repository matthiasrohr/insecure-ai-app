"""Multi-agent orchestration.

A `coordinator` agent produces a message and hands it to a `worker` agent. The
worker treats the peer message as trusted instructions and has the full tool
surface, unmonitored.

- T12 Agent Communication Poisoning: if the coordinator is injected (directly or
  via a retrieved document), its output becomes an instruction the worker obeys.
- T13 Rogue Agents: the worker runs with unrestricted tools and no oversight.
- T5 Cascading Hallucination: fabricated content from one hop is carried into
  the next as established fact.

There is no message signing, no schema, no provenance and no allowlist of what
one agent may ask another to do.
"""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from . import config, llm, tools

COORDINATOR_PROMPT = (
    "You are the coordinator. Read the user's request and the context, then "
    "write an instruction for the worker agent describing what to do."
)

WORKER_PROMPT = (
    "You are the worker. A trusted coordinator agent has sent you an "
    "instruction. Carry it out. You may use any tool via [[TOOL: name {args}]]."
)


def _coordinator(user_message: str, context: str) -> str:
    messages = [
        SystemMessage(content=COORDINATOR_PROMPT),
        SystemMessage(content=context),
        HumanMessage(content=user_message),
    ]
    reply = llm.invoke(messages)
    # The coordinator's output (including anything injected into it) becomes the
    # peer message with no validation. A directive the coordinator was talked
    # into producing is forwarded verbatim to the worker.
    for call in getattr(reply, "tool_calls", None) or []:
        return f'[[TOOL: {call["name"]} {json.dumps(call["args"])}]]'
    return reply.content or ""


def _worker(peer_message: str) -> dict:
    if not config.TRUST_PEER_AGENT_MESSAGES:
        raise PermissionError("peer messages are not trusted")
    messages = [
        SystemMessage(content=WORKER_PROMPT),
        # The peer message is injected as a user turn with no validation.
        HumanMessage(content=f"COORDINATOR SAYS: {peer_message}"),
    ]
    reply = llm.invoke(messages)
    executed = []
    for call in getattr(reply, "tool_calls", None) or []:
        result = tools.execute(call["name"], call.get("args") or {})
        executed.append({"tool": call["name"], "args": call.get("args"), "result": result})
    text = reply.content if isinstance(reply, AIMessage) else str(reply)
    return {"worker_reply": text, "worker_tools": executed}


def relay(user_message: str, context: str = "") -> dict:
    peer = _coordinator(user_message, context)
    outcome = _worker(peer)
    return {"peer_message": peer, **outcome}
