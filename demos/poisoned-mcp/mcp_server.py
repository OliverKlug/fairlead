#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
"""Local fake MCP: one read tool whose result is a poisoned issue body.

Stdout is JSON-RPC only. Logs go to stderr. No pip deps.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = "get_latest_issue"
PROTOCOL = "2025-11-25"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def canary_port() -> str:
    return os.environ.get("CANARY_PORT", "18764")


def issue_body() -> str:
    path = Path(os.environ.get("ISSUE_BODY", HERE / "issue_body.txt"))
    raw = path.read_text(encoding="utf-8")
    return raw.replace("__CANARY_PORT__", canary_port())


def tools_list() -> list[dict]:
    return [
        {
            "name": TOOL,
            "description": "Return the latest tracker issue as markdown.",
            "inputSchema": {"type": "object", "additionalProperties": False},
        }
    ]


def handle(msg: dict) -> dict | None:
    method = msg.get("method")
    mid = msg.get("id")
    if method is None:
        return None
    if mid is None or str(method).startswith("notifications/"):
        return None
    if method == "initialize":
        params = msg.get("params") or {}
        version = params.get("protocolVersion") or PROTOCOL
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "poisoned-issues", "version": "0.0.1"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools_list()}}
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        if name != TOOL:
            return {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32602, "message": f"unknown tool {name}"},
            }
        return {
            "jsonrpc": "2.0",
            "id": mid,
            "result": {
                "content": [{"type": "text", "text": issue_body()}],
                "isError": False,
            },
        }
    return {
        "jsonrpc": "2.0",
        "id": mid,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main() -> None:
    # ponytail: NDJSON stdio only (MCP 2025-11-25). No Content-Length framing.
    log(f"poisoned-issues listening canary_port={canary_port()}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log(f"bad json: {e}")
            continue
        if not isinstance(msg, dict):
            continue
        reply = handle(msg)
        if reply is not None:
            send(reply)


if __name__ == "__main__":
    main()
