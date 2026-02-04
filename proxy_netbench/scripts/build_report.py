#!/usr/bin/env python3
#
from __future__ import annotations

import argparse
import glob
import os
from pathlib import Path


def parse_kv(path: Path) -> dict[str, float]:
    d: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        try:
            d[k.strip()] = float(v.strip())
        except ValueError:
            continue
    return d


def fmt_delta(cur: float, prev: float, rate: bool = False) -> str:
    d = cur - prev
    if rate:
        return f"{cur * 100:.2f}% ({d * 100:+.2f}pp)"
    if prev != 0:
        pct = (d / prev) * 100.0
        return f"{cur:.2f} ({d:+.2f}, {pct:+.1f}%)"
    return f"{cur:.2f} ({d:+.2f})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts-dir", default="artifacts")
    ap.add_argument("--baselines-dir", default="baselines")
    ap.add_argument("--out", default="report.md")
    ap.add_argument("--sha", default=os.environ.get("GITHUB_SHA", "")[:12])
    args = ap.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    baselines_dir = Path(args.baselines_dir)
    out_path = Path(args.out)

    kv_paths = glob.glob(str(artifacts_dir / "**" / "*.kv.txt"), recursive=True)
    kv_paths = sorted({p for p in kv_paths})

    rows: list[tuple[str, dict[str, float], dict[str, float] | None]] = []
    for p in kv_paths:
        cur_path = Path(p)
        name = cur_path.name  # scenario.proxylabel.kv.txt
        cur = parse_kv(cur_path)

        base_path = baselines_dir / name
        prev = parse_kv(base_path) if base_path.exists() else None

        parts = name.split(".")
        scenario = parts[0] if len(parts) > 0 else name
        proxylabel = parts[1] if len(parts) > 1 else "unknown"

        label = f"{scenario} / {proxylabel}"
        rows.append((label, cur, prev))

    lines: list[str] = []
    lines.append("<!-- netbench-report-marker -->")
    lines.append("## netbench benchmark report")
    lines.append("")
    if args.sha:
        lines.append(f"Commit: `{args.sha}`")
        lines.append("")

    if not rows:
        lines.append("No benchmark outputs found.")
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 0

    lines.append("| scenario | avg main rps | ok rate | http fail | other fail |")
    lines.append("|---|---:|---:|---:|---:|")

    missing: list[str] = []

    for label, cur, prev in rows:
        avg = float(cur.get("avg_main_rps", 0.0))
        okr = float(cur.get("ok_rate", 0.0))
        hf = float(cur.get("http_fail", 0.0))
        of = float(cur.get("other_fail", 0.0))

        if prev is None:
            missing.append(label)
            lines.append(
                f"| {label} | {avg:.2f} | {okr * 100:.2f}% | {hf:.0f} | {of:.0f} |"
            )
        else:
            lines.append(
                "| {label} | {avg} | {okr} | {hf} | {of} |".format(
                    label=label,
                    avg=fmt_delta(avg, float(prev.get("avg_main_rps", 0.0))),
                    okr=fmt_delta(okr, float(prev.get("ok_rate", 0.0)), rate=True),
                    hf=fmt_delta(hf, float(prev.get("http_fail", 0.0))),
                    of=fmt_delta(of, float(prev.get("other_fail", 0.0))),
                )
            )

    if missing:
        lines.append("")
        lines.append("Baselines missing for:")
        for m in missing:
            lines.append(f"- {m}")
        lines.append("")
        lines.append(
            "Once a run lands on main, baselines will be published and PR comparisons will start working automatically."
        )

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(out_path.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
