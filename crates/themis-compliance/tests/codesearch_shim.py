#!/usr/bin/env python3
"""Tiny stdlib-only MCP shim used in CI for the CodeSearch MCP federation test.

The real @apohara/codesearch-mcp is a Node.js package that lives in
the `mcp` profile of docker-compose.yml (see docker-compose.yml).
For CI (and local development on hosts without Node + npm), this
shim stands in. It speaks JSON-RPC 2.0 over plain HTTP and
implements exactly three methods:

  - initialize       → returns a fixed server info + capabilities
  - tools/list       → advertises the `code_search` tool
  - tools/call       → executes `code_search` and returns an empty
                        result list (matches the production server's
                        response when there is no indexed corpus)

Wire-compatible with the C-11 mcp_proxy in
crates/themis-orchestrator/src/mcp_proxy.rs. The proxy speaks
JSON-RPC over HTTP at /mcp; the shim listens on a single HTTP
endpoint and routes by `method`.

Run: `python3 codesearch_shim.py --port 3000`.

No external Python deps. Uses only `http.server`, `json`, and
`argparse` from the stdlib. Stdout is reserved for the PID file
handshake (see scripts/start-codesearch.sh).
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SERVER_INFO = {
    "name": "apohara-codesearch-mcp-shim",
    "version": "0.1.0",
}

SERVER_CAPABILITIES = {
    "tools": {"listChanged": False},
}

TOOL_DEFINITION = {
    "name": "code_search",
    "description": (
        "Search the indexed source corpus. Returns matching files "
        "with line numbers and snippets. The CI shim returns an "
        "empty result list; the production Node server indexes "
        "crates/, scripts/, and themis-agentgateway/ConfigMap/."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query"},
        },
        "required": ["query"],
    },
}


def make_result(request_id: Any, result: Any) -> dict[str, Any]:
    """Wrap a successful result in a JSON-RPC 2.0 envelope."""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def make_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    """Wrap an error in a JSON-RPC 2.0 envelope."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_rpc(request: dict[str, Any]) -> dict[str, Any]:
    """Route a JSON-RPC 2.0 request to its handler.

    Unknown methods return -32601 (Method not found). Invalid
    params return -32602 (Invalid params). Anything else is the
    caller's problem and surfaces as -32600 (Invalid Request).
    """
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    if not isinstance(method, str):
        return make_error(request_id, -32600, "missing method")

    if method == "initialize":
        return make_result(
            request_id,
            {
                "protocolVersion": "2024-11-05",
                "serverInfo": SERVER_INFO,
                "capabilities": SERVER_CAPABILITIES,
            },
        )

    if method == "notifications/initialized":
        # Notification, not a request; per JSON-RPC 2.0 we MUST
        # NOT respond. The proxy still expects a 204.
        return {}

    if method == "tools/list":
        return make_result(request_id, {"tools": [TOOL_DEFINITION]})

    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str):
            return make_error(request_id, -32602, "params.name must be a string")
        if name != "code_search":
            return make_error(
                request_id,
                -32602,
                f"unknown tool {name!r}; only code_search is supported",
            )
        query = arguments.get("query")
        if not isinstance(query, str) or not query.strip():
            return make_error(
                request_id,
                -32602,
                "params.arguments.query must be a non-empty string",
            )
        # The shim returns an empty corpus — production behavior
        # is identical when there is no indexed repository.
        return make_result(
            request_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "query": query,
                                "matches": [],
                                "shim": True,
                            }
                        ),
                    }
                ],
                "isError": False,
            },
        )

    return make_error(request_id, -32601, f"method {method!r} not found")


class ShimHandler(BaseHTTPRequestHandler):
    """HTTP handler that speaks JSON-RPC 2.0 at /mcp.

    Body MUST be a single JSON object (the JSON-RPC request).
    Batches are accepted as a top-level array per JSON-RPC 2.0
    §6 — the proxy in themis-orchestrator/src/mcp_proxy.rs only
    forwards single-object requests, so we keep this path
    simple.
    """

    # Silence the default per-request stderr access log; the
    # caller cares about PID + bind port, not request traces.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _write_json(self, status: int, body: dict[str, Any] | list[Any]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:  # noqa: N802 — http.server API
        if self.path != "/mcp":
            self._write_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            self._write_json(
                400,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc}"},
                },
            )
            return

        if isinstance(payload, list):
            responses = [handle_rpc(item) for item in payload]
            # Filter out empty notifications (no id, no result/error).
            responses = [r for r in responses if r]
            self._write_json(200, responses)
            return

        if not isinstance(payload, dict):
            self._write_json(
                400,
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "request must be an object"},
                },
            )
            return

        response = handle_rpc(payload)
        if not response:
            # notification/initialized → no response body, 204.
            self.send_response(204)
            self.end_headers()
            return
        self._write_json(200, response)

    def do_GET(self) -> None:  # noqa: N802 — http.server API
        # Health check used by scripts/start-codesearch.sh.
        if self.path in ("/", "/health", "/healthz"):
            self._write_json(200, {"status": "ok", "server": SERVER_INFO["name"]})
            return
        self._write_json(404, {"error": "not found"})


def main() -> int:
    parser = argparse.ArgumentParser(description="Apohara CodeSearch MCP shim (CI fallback).")
    parser.add_argument("--port", type=int, default=3000, help="port to bind (default: 3000)")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), ShimHandler)
    print(f"codesearch-mcp shim listening on http://{args.host}:{args.port}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
