#!/usr/bin/env python3
#
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def api_get(url: str, token: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "netbench-baseline-downloader",
        },
        method="GET",
    )
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_download(url: str, token: str, dest: Path) -> None:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "netbench-baseline-downloader",
        },
        method="GET",
    )
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    with urllib.request.urlopen(req) as resp, dest.open("wb") as f:
        while True:
            chunk = resp.read(1024 * 128)
            if not chunk:
                break
            f.write(chunk)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument(
        "--workflow", required=True, help="workflow file name, e.g. proxy-benchmark.yml"
    )
    ap.add_argument(
        "--artifact", required=True, help="artifact name, e.g. netbench-baselines"
    )
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("GITHUB_TOKEN is required")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    base = "https://api.github.com"
    owner, repo = args.repo.split("/", 1)

    runs_url = f"{base}/repos/{owner}/{repo}/actions/workflows/{urllib.parse.quote(args.workflow)}/runs?branch={urllib.parse.quote(args.branch)}&status=success&per_page=1"
    runs = api_get(runs_url, token)
    runs_list = runs.get("workflow_runs", [])
    if not runs_list:
        eprint("No successful workflow runs found for branch", args.branch)
        return 0

    run_id = runs_list[0]["id"]

    arts_url = f"{base}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
    arts = api_get(arts_url, token).get("artifacts", [])
    hit = None
    for a in arts:
        if a.get("name") == args.artifact:
            hit = a
            break

    if not hit:
        eprint("Baseline artifact not found in run", run_id)
        return 0

    art_id = hit["id"]
    zip_url = f"{base}/repos/{owner}/{repo}/actions/artifacts/{art_id}/zip"
    zip_path = out_dir / "baselines.zip"

    eprint("Downloading baseline artifact", args.artifact, "from run", run_id)
    api_download(zip_url, token, zip_path)

    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(out_dir)

    zip_path.unlink(missing_ok=True)

    eprint("Baselines extracted into", str(out_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
