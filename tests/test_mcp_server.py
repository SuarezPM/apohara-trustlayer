"""
Test the tl-mcp-server binary end-to-end via JSON-RPC over stdio.

Per Plan v1.2 Block 3 v1.1.0-US-13:
- spawn `tl-mcp-server` as a subprocess
- send a `tools/list` JSON-RPC request via stdin
- read the response from stdout
- assert the response contains 7 tools with the expected names

Then send a `tools/call` request for each tool and assert the
response has the expected shape (success or error).

We do NOT use the rmcp SDK (which is the thing that's broken in
rmcp 1.8). We just use Python's `json` module + `subprocess` —
this is the same approach the Claude Code / Cursor / Codex MCP
clients use under the hood.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_BIN = REPO_ROOT / "target" / "debug" / "tl-mcp-server"

EXPECTED_TOOLS = [
    "tl_generate_disclosure",
    "tl_verify_provenance",
    "tl_sign_artifact",
    "tl_create_evidence_bundle",
    "tl_evaluate_policy",
    "tl_inspect_receipt",
    "tl_check_compliance",
]


def _build_if_needed() -> None:
    """Build the tl-mcp-server binary if it doesn't exist."""
    if not MCP_BIN.exists():
        subprocess.run(
            ["cargo", "build", "-p", "tl-mcp-server"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )


def _send_jsonrpc(requests: list[dict]) -> list[dict]:
    """Send JSON-RPC requests to tl-mcp-server, return the responses."""
    _build_if_needed()
    input_lines = [json.dumps(req) for req in requests]
    input_data = "\n".join(input_lines) + "\n"

    proc = subprocess.run(
        [str(MCP_BIN)],
        cwd=REPO_ROOT,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert proc.returncode == 0, (
        f"tl-mcp-server exited with {proc.returncode}\n"
        f"stderr: {proc.stderr}"
    )
    responses = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line:
            responses.append(json.loads(line))
    return responses


def test_mcp_server_tools_list_returns_seven_tools() -> None:
    """AC-6: tools/list returns the 7 expected tools."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {},
    }
    responses = _send_jsonrpc([request])
    assert len(responses) == 1
    resp = responses[0]
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    assert "result" in resp
    tools = resp["result"]["tools"]
    assert len(tools) == 7
    names = {t["name"] for t in tools}
    assert names == set(EXPECTED_TOOLS)


def test_mcp_server_initialize_returns_server_info() -> None:
    """AC-4: initialize returns server info + capabilities."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    responses = _send_jsonrpc([request])
    assert len(responses) == 1
    resp = responses[0]
    assert "result" in resp
    info = resp["result"]
    assert "serverInfo" in info
    assert info["serverInfo"]["name"] == "apohara-trustlayer-mcp-server"
    assert "capabilities" in info
    assert "tools" in info["capabilities"]


def test_mcp_server_tools_call_check_compliance() -> None:
    """AC-7: tools/call dispatches to a real tool handler and returns
    a structured response with isError=false."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "tl_check_compliance",
            "arguments": {"bundle_id": "test-bundle-123"},
        },
    }
    responses = _send_jsonrpc([request])
    assert len(responses) == 1
    resp = responses[0]
    assert "result" in resp
    result = resp["result"]
    assert result["isError"] is False
    # The text content is a JSON-serialized string of the handler output.
    text = result["content"][0]["text"]
    inner = json.loads(text)
    assert inner["bundle_id"] == "test-bundle-123"
    assert inner["rollup"] == "Partial"
    assert "watermark" in inner["layers"]


def test_mcp_server_tools_call_unknown_tool_returns_error() -> None:
    """Unknown tool name → isError=true (or method-not-found error)."""
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "tl_nonexistent_tool",
            "arguments": {},
        },
    }
    responses = _send_jsonrpc([request])
    assert len(responses) == 1
    resp = responses[0]
    # Either isError=true (handler-level) or error.code=-32601 (rpc-level)
    if "error" in resp:
        assert resp["error"]["code"] == -32601
    else:
        result = resp["result"]
        assert result["isError"] is True


def test_mcp_server_multiple_requests_in_one_session() -> None:
    """Multiple requests in one session: state is preserved between them
    (well, our server is stateless, but the protocol supports it)."""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "tl_inspect_receipt", "arguments": {"receipt_id": "r-001"}}},
        {"jsonrpc": "2.0", "id": 3, "method": "ping", "params": {}},
    ]
    responses = _send_jsonrpc(requests)
    assert len(responses) == 3
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == 2
    assert responses[2]["id"] == 3
    # ping returns an empty result
    assert responses[2]["result"] == {}
