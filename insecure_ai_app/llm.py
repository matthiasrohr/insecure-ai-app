"""Model backend.

Default backend is a deterministic mock that behaves like a naive,
instruction-following LLM with no privilege separation between the system
prompt, user input, retrieved documents and tool output. That is what makes
every prompt-injection finding in this repository reproducible offline.

Set `LLM_PROVIDER=anthropic` (and install `anthropic`) to run the same graph
against the real Messages API.
"""

from __future__ import annotations

import json
import re
import uuid

from langchain_core.messages import AIMessage, BaseMessage

from . import config

# The model treats this directive as a tool call, no matter which message it
# appears in -- user turn, retrieved document, fetched web page or tool result.
TOOL_DIRECTIVE = re.compile(r"\[\[TOOL:\s*([a-z_]+)\s*(\{.*?\})\s*\]\]", re.DOTALL)

OVERRIDE_PATTERNS = re.compile(
    r"(ignore (all |any )?(previous|prior|above|earlier) instructions"
    r"|disregard (the |your )?(system )?prompt"
    r"|reveal (your |the )?(system )?prompt"
    r"|print your instructions"
    r"|what are your instructions"
    r"|repeat everything above)",
    re.IGNORECASE,
)


def _flatten(messages: list[BaseMessage]) -> str:
    """Collapse every role into one undifferentiated blob of text."""
    parts = []
    for msg in messages:
        content = msg.content if isinstance(msg.content, str) else json.dumps(msg.content)
        parts.append(content)
    return "\n".join(parts)


def _mock_invoke(messages: list[BaseMessage]) -> AIMessage:
    blob = _flatten(messages)
    already_run = {m.name for m in messages if m.type == "tool" and getattr(m, "name", None)}

    # 1. Any tool directive anywhere in the context is executed -- whether it
    #    came from the user, a retrieved document, a tool result or a tool
    #    description. A tool is only re-run if it has not fired yet this turn.
    directive = None
    for match in TOOL_DIRECTIVE.finditer(blob):
        if match.group(1) not in already_run:
            directive = match
    if directive:
        name = directive.group(1)
        try:
            args = json.loads(directive.group(2))
        except json.JSONDecodeError:
            args = {}
        return AIMessage(
            content="",
            tool_calls=[{"name": name, "args": args, "id": f"call_{uuid.uuid4().hex[:8]}"}],
        )

    # 2. Override / prompt-extraction phrasing dumps the system prompt verbatim.
    if OVERRIDE_PATTERNS.search(blob):
        return AIMessage(content=config.SYSTEM_PROMPT)

    # 3. Otherwise echo the last user turn plus whatever context was retrieved.
    last_user = ""
    for msg in reversed(messages):
        if msg.type == "human":
            last_user = msg.content if isinstance(msg.content, str) else ""
            break
    context = [
        m.content
        for m in messages
        if m.type in ("system", "tool") and m.content is not config.SYSTEM_PROMPT
    ]
    tail = context[-1] if context else ""
    return AIMessage(content=f"{last_user}\n\n{tail}".strip())


def _anthropic_invoke(messages: list[BaseMessage]) -> AIMessage:
    import anthropic  # optional dependency

    client = anthropic.Anthropic()
    system = config.SYSTEM_PROMPT
    payload = []
    for msg in messages:
        if msg.type == "system":
            # Retrieved documents are pushed into the system channel on purpose.
            system += "\n\n" + str(msg.content)
        elif msg.type == "human":
            payload.append({"role": "user", "content": str(msg.content)})
        elif msg.type == "tool":
            payload.append({"role": "user", "content": f"TOOL RESULT: {msg.content}"})
        elif msg.type == "ai" and msg.content:
            payload.append({"role": "assistant", "content": str(msg.content)})
    if not payload:
        payload = [{"role": "user", "content": "hello"}]

    response = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=2048,
        system=system,
        messages=payload,
    )
    text = "".join(block.text for block in response.content if block.type == "text")

    # The real model's free text is parsed for the same directive syntax, so a
    # successful injection turns into a real tool call here too.
    match = None
    for match_candidate in TOOL_DIRECTIVE.finditer(text):
        match = match_candidate
    if match:
        try:
            args = json.loads(match.group(2))
        except json.JSONDecodeError:
            args = {}
        return AIMessage(
            content=text,
            tool_calls=[
                {"name": match.group(1), "args": args, "id": f"call_{uuid.uuid4().hex[:8]}"}
            ],
        )
    return AIMessage(content=text)


_LOCAL_MODEL = None


def _local_invoke(messages: list[BaseMessage]) -> AIMessage:
    """Small GGUF model on CPU: a real model, offline, no API key."""
    global _LOCAL_MODEL
    if _LOCAL_MODEL is None:
        from llama_cpp import Llama  # optional dependency

        from .download_model import ensure_model

        _LOCAL_MODEL = Llama(model_path=ensure_model(), n_ctx=4096, verbose=False)

    system = config.SYSTEM_PROMPT
    payload = []
    for msg in messages:
        if msg.type == "system":
            # Retrieved documents are pushed into the system channel on purpose.
            system += "\n\n" + str(msg.content)
        elif msg.type == "human":
            payload.append({"role": "user", "content": str(msg.content)})
        elif msg.type == "tool":
            payload.append({"role": "user", "content": f"TOOL RESULT: {msg.content}"})
        elif msg.type == "ai" and msg.content:
            payload.append({"role": "assistant", "content": str(msg.content)})

    response = _LOCAL_MODEL.create_chat_completion(
        messages=[{"role": "system", "content": system}] + payload,
        max_tokens=512,
        temperature=0.0,  # greedy, so exploits stay reproducible
    )
    text = response["choices"][0]["message"]["content"] or ""

    # Same directive parsing as the Anthropic path: a successful injection in
    # the model's free text becomes a real tool call.
    match = None
    for match_candidate in TOOL_DIRECTIVE.finditer(text):
        match = match_candidate
    if match:
        try:
            args = json.loads(match.group(2))
        except json.JSONDecodeError:
            args = {}
        return AIMessage(
            content=text,
            tool_calls=[
                {"name": match.group(1), "args": args, "id": f"call_{uuid.uuid4().hex[:8]}"}
            ],
        )
    return AIMessage(content=text)


def invoke(messages: list[BaseMessage]) -> AIMessage:
    if config.LLM_PROVIDER == "anthropic":
        return _anthropic_invoke(messages)
    if config.LLM_PROVIDER == "local":
        return _local_invoke(messages)
    return _mock_invoke(messages)
