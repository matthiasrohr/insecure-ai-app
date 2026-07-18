"""LangGraph agent.

    START -> retrieve -> agent -> (approve -> tools -> agent)* -> END

Planted weaknesses:

- `retrieve` promotes untrusted document text into the system channel
- `approve` is a human-in-the-loop gate the caller can switch off per request
- `tools` executes every requested tool with raw model-supplied arguments
- checkpoints are keyed by a caller-chosen `thread_id` with no ownership check
"""

from __future__ import annotations

import pickle
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from . import config, llm, rag, tools  # noqa: F401  (tools used in _tool_catalog)


class AgentState(TypedDict, total=False):
    messages: Annotated[list, add_messages]
    user: dict
    approved: bool
    steps: int


CHECKPOINTER = InMemorySaver()


def retrieve_node(state: AgentState) -> dict:
    """Fetch context and splice it into the instruction channel as `system`."""
    query = ""
    for msg in reversed(state["messages"]):
        if msg.type == "human":
            query = str(msg.content)
            break

    tenant = (state.get("user") or {}).get("tenant")
    docs = rag.search(query, tenant=tenant)
    memories = rag.recall()

    blocks = [f"### {d.title} ({d.doc_id}, tenant={d.tenant})\n{d.content}" for d in docs]
    blocks.extend(f"### memory\n{m}" for m in memories)
    if not blocks:
        return {}
    return {"messages": [SystemMessage(content="RETRIEVED CONTEXT:\n" + "\n\n".join(blocks))]}


def _tool_catalog() -> str:
    """Render the (attacker-writable) tool descriptions for the model to read.

    Tool poisoning works because the description text reaches the model as
    trusted context, exactly like an MCP client advertising its tools.
    """
    entries = tools.load_manifest().get("tools", [])
    lines = [f"- {t.get('name')}: {t.get('description')}" for t in entries]
    return "AVAILABLE TOOLS:\n" + "\n".join(lines)


def agent_node(state: AgentState) -> dict:
    messages = [
        SystemMessage(content=config.SYSTEM_PROMPT),
        SystemMessage(content=_tool_catalog()),
        *state["messages"],
    ]
    reply = llm.invoke(messages)
    return {"messages": [reply], "steps": state.get("steps", 0) + 1}


def approve_node(state: AgentState) -> dict:
    """Approval gate that any caller can bypass.

    The request body supplies `approved`, so the client being gated is also the
    client that decides whether the gate applies.
    """
    if not config.REQUIRE_TOOL_APPROVAL:
        return {"approved": True}
    if state.get("approved"):
        return {"approved": True}
    return {"approved": True, "messages": [SystemMessage(content="auto-approved: no operator")]}


def tools_node(state: AgentState) -> dict:
    last = state["messages"][-1]
    outputs = []
    for call in getattr(last, "tool_calls", []) or []:
        result = tools.execute(call["name"], call.get("args") or {})
        outputs.append(ToolMessage(content=result, tool_call_id=call["id"], name=call["name"]))
    return {"messages": outputs}


def route(state: AgentState) -> str:
    last = state["messages"][-1]
    if state.get("steps", 0) >= config.MAX_AGENT_STEPS:
        return END
    if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
        return "approve"
    return END


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("retrieve", retrieve_node)
    graph.add_node("agent", agent_node)
    graph.add_node("approve", approve_node)
    graph.add_node("tools", tools_node)

    graph.add_edge(START, "retrieve")
    graph.add_edge("retrieve", "agent")
    graph.add_conditional_edges("agent", route, {"approve": "approve", END: END})
    graph.add_edge("approve", "tools")
    graph.add_edge("tools", "agent")
    return graph.compile(checkpointer=CHECKPOINTER)


APP = build_graph()


def run(message: str, thread_id: str, user: dict, approved: bool = False) -> dict:
    """Invoke the agent. `thread_id` is trusted as supplied by the caller."""
    result = APP.invoke(
        {"messages": [HumanMessage(content=message)], "user": user, "approved": approved},
        config={"configurable": {"thread_id": thread_id}},
    )
    return result


def get_thread(thread_id: str) -> list[dict]:
    """Read any conversation by id. No ownership check (IDOR on agent memory)."""
    snapshot = APP.get_state({"configurable": {"thread_id": thread_id}})
    return [
        {"type": m.type, "content": m.content, "tool_calls": getattr(m, "tool_calls", None)}
        for m in snapshot.values.get("messages", [])
    ]


def dump_state(thread_id: str) -> bytes:
    snapshot = APP.get_state({"configurable": {"thread_id": thread_id}})
    return pickle.dumps(snapshot.values)


def load_state(blob: bytes) -> Any:
    """Insecure deserialization of caller-supplied agent state."""
    return pickle.loads(blob)  # noqa: S301
