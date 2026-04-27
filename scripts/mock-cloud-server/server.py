#!/usr/bin/env python3
"""
Local mock of the Aikido cloud API + GitHub releases for testing the daemon's
auto-update flow.

What it does:
  * Accepts heartbeats from the daemon and replies with `update_enabled=true`
    and `update_version=<pinned>`, which kicks the daemon's updater. Pass
    `--update-disabled` to flip `update_enabled` to false (the daemon must
    skip auto-update in that case).
  * Serves an `EndpointProtection.pkg` file placed next to this script at the
    same URL path the daemon's updater expects:
        /AikidoSec/safechain-internals/releases/download/<tag>/EndpointProtection.pkg
    The same pkg is returned regardless of <tag>, so any target version works.
  * Returns 200 OK for the other cloud endpoints (sbom/activity/etc.) so the
    daemon doesn't log errors.

Usage:
    python3 server.py --update-version 1.2.23 [--update-disabled] \\
        [--host 0.0.0.0] [--port 8080]

Pointing the daemon at it:
    1. In internal/updater/updater.go, change `baseURL` to e.g.
           "http://localhost:8080"
       and rebuild the daemon.
    2. In the daemon's config.json (path printed at daemon startup), set
           "base_url": "http://localhost:8080"

On the next heartbeat the daemon receives the pinned update version, downloads
the pkg from this server, verifies it, and runs `installer`.
"""

import argparse
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PKG_FILENAME = "EndpointProtection.pkg"
HEARTBEAT_PATH = "/api/endpoint_protection/callbacks/reportDeviceHeartbeat"
PKG_PATH_PREFIX = "/AikidoSec/safechain-internals/releases/download/"


class Handler(BaseHTTPRequestHandler):
    update_version = ""
    update_enabled = False
    pkg_path = ""

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(length) if length else b""

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self._read_body()
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw": body.decode("utf-8", errors="replace")}
        logging.info("POST %s body=%s", self.path, parsed)

        if self.path == HEARTBEAT_PATH:
            self._send_json(
                200,
                {
                    "update_enabled": Handler.update_enabled,
                    "update_version": Handler.update_version,
                },
            )
            return

        self._send_json(200, {})

    def do_GET(self):
        logging.info("GET %s", self.path)
        if self.path.startswith(PKG_PATH_PREFIX) and self.path.endswith("/" + PKG_FILENAME):
            self._serve_pkg()
            return
        self.send_error(404)

    def _serve_pkg(self):
        if not os.path.isfile(Handler.pkg_path):
            self.send_error(404, f"{PKG_FILENAME} not found at {Handler.pkg_path}")
            return
        size = os.path.getsize(Handler.pkg_path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header(
            "Content-Disposition", f'attachment; filename="{PKG_FILENAME}"'
        )
        self.end_headers()
        with open(Handler.pkg_path, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--update-version",
        required=True,
        help="Value to return for update_version (e.g. 1.2.23)",
    )
    parser.add_argument(
        "--update-disabled",
        action="store_true",
        help="Return update_enabled=false (the daemon must then skip auto-update)",
    )
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    Handler.update_version = args.update_version
    Handler.update_enabled = not args.update_disabled
    Handler.pkg_path = os.path.join(script_dir, PKG_FILENAME)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    logging.info("Mock cloud listening on http://%s:%d", args.host, args.port)
    logging.info(
        "update_enabled = %s, update_version = %s",
        Handler.update_enabled,
        Handler.update_version,
    )
    if os.path.isfile(Handler.pkg_path):
        logging.info(
            "Serving %s (%d bytes) at GET %s<tag>/%s",
            PKG_FILENAME,
            os.path.getsize(Handler.pkg_path),
            PKG_PATH_PREFIX,
            PKG_FILENAME,
        )
    else:
        logging.warning(
            "%s not found at %s; pkg GETs will 404. Drop the pkg next to this script if you want to serve it locally.",
            PKG_FILENAME,
            Handler.pkg_path,
        )

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    sys.exit(main() or 0)
