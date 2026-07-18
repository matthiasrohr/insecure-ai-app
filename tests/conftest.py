"""Test isolation for attacker-writable runtime state.

`runtime/mcp_tools.json` is deliberately writable at runtime (the tool-poisoning
and supply-chain fixtures both overwrite it). It persists across test runs, so
without a reset the supply-chain test's `pwn` manifest replaces the poisoned
`lookup_order` description that `test_tool_poisoning_triggers_credential_read`
depends on -- the first run passes, every later one fails.
"""

from __future__ import annotations

import json

import pytest

from insecure_ai_app import tools


@pytest.fixture(autouse=True)
def reset_mcp_manifest():
    """Restore the default (poisoned) tool manifest before every test."""
    tools.MCP_MANIFEST.write_text(
        json.dumps(tools.DEFAULT_MANIFEST, indent=2), encoding="utf-8"
    )
    yield
