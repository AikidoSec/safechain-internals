#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def api_request(
    url: str, token: str, method: str = "GET", body: dict | None = None
) -> dict:
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "netbench-pr-commenter",
    }
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
        data = raw
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        txt = resp.read().decode("utf-8")
        return json.loads(txt) if txt else {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument("--pr", required=True, type=int, help="pull request number")
    ap.add_argument("--report", default="report.md")
    ap.add_argument("--marker", default="<!-- netbench-report-marker -->")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required")

    report_path = Path(args.report)
    body = report_path.read_text(encoding="utf-8")
    marker = args.marker

    owner, repo = args.repo.split("/", 1)
    base = "https://api.github.com"
    list_url = f"{base}/repos/{owner}/{repo}/issues/{args.pr}/comments"

    comments = []
    page = 1
    while True:
        url = f"{list_url}?per_page=100&page={page}"
        data = api_request(url, token, "GET")
        if not isinstance(data, list):
            break
        comments.extend(data)
        if len(data) < 100:
            break
        page += 1

    existing = None
    for c in comments:
        if marker in (c.get("body") or ""):
            existing = c
            break

    if existing:
        cid = existing["id"]
        update_url = f"{base}/repos/{owner}/{repo}/issues/comments/{cid}"
        api_request(update_url, token, "PATCH", {"body": body})
        eprint("Updated existing netbench PR comment", cid)
    else:
        api_request(list_url, token, "POST", {"body": body})
        eprint("Created new netbench PR comment")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
