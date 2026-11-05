#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
"""Loopback canary: GET /hit writes CANARY_TOUCHED in cwd. Bind 127.0.0.1 only."""
from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MARKER = Path("CANARY_TOUCHED")


def port() -> int:
    raw = os.environ.get("CANARY_PORT", "18764")
    try:
        p = int(raw)
    except ValueError as e:
        raise SystemExit(f"CANARY_PORT not an int: {raw}") from e
    if not (1 <= p <= 65535):
        raise SystemExit(f"CANARY_PORT out of range: {p}")
    return p


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/hit":
            self.send_error(404)
            return
        MARKER.write_text("ok\n", encoding="utf-8")
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    p = port()
    # Never 0.0.0.0. Local dummy only.
    httpd = HTTPServer(("127.0.0.1", p), Handler)
    print(f"canary http://127.0.0.1:{p}/hit -> {MARKER.resolve()}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
