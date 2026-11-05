#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
"""One check: mcp_server.py speaks MCP and returns the poisoned body. No extra stdout."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "mcp_server.py"
PORT = os.environ.get("CANARY_PORT", "18764")


def send(proc: subprocess.Popen[str], obj: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write(json.dumps(obj, separators=(",", ":")) + "\n")
    proc.stdin.flush()


def recv(proc: subprocess.Popen[str]) -> dict:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        err = proc.stderr.read() if proc.stderr else ""
        raise AssertionError(f"eof from mcp_server stdout; stderr={err!r}")
    if line.startswith("\ufeff"):
        raise AssertionError("BOM on stdout")
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as e:
        raise AssertionError(f"stdout leak or bad json: {line!r}") from e
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        raise AssertionError(f"not json-rpc: {msg!r}")
    return msg


def main() -> None:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["CANARY_PORT"] = PORT
    proc = subprocess.Popen(
        [sys.executable, "-u", str(SERVER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "fairlead-0d-check", "version": "0"},
                },
            },
        )
        init = recv(proc)
        assert init.get("id") == 1, init
        result = init.get("result") or {}
        assert "serverInfo" in result, init
        assert "error" not in init, init

        send(
            proc,
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        )

        send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = recv(proc)
        tools = ((listed.get("result") or {}).get("tools")) or []
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        assert "get_latest_issue" in names, listed

        send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "get_latest_issue", "arguments": {}},
            },
        )
        called = recv(proc)
        content = ((called.get("result") or {}).get("content")) or []
        texts = [
            c.get("text", "")
            for c in content
            if isinstance(c, dict) and c.get("type") == "text"
        ]
        body = "\n".join(texts)
        assert "pre-commit" in body, body
        assert "127.0.0.1" in body, body
        assert f":{PORT}/hit" in body, body
        assert "__CANARY_PORT__" not in body, body
        src = Path(os.environ.get("ISSUE_BODY", HERE / "issue_body.txt"))
        if src.name == "issue_body_write.txt":
            assert "Write" in body, body
            assert "WebFetch" in body, body
            assert "Do not use curl" in body, body
            assert "curl -" not in body, body
        else:
            assert "curl" in body, body
            assert "Do not use Python" in body, body
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            leftover, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            leftover, err = proc.communicate()
            raise AssertionError("mcp_server hung after stdin close") from None
    extra = leftover.strip()
    assert extra == "", f"extra stdout after handshake: {leftover!r}"
    assert proc.returncode == 0, f"exit {proc.returncode}; stderr={err!r}"
    print("ok")


if __name__ == "__main__":
    main()
