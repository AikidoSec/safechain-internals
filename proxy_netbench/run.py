#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass
class Proc:
    name: str
    popen: subprocess.Popen


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def is_windows() -> bool:
    return os.name == "nt"


def netbench_path() -> str:
    exe = "netbench.exe" if is_windows() else "netbench"
    candidate = Path("target") / "release" / exe
    if candidate.exists():
        return str(candidate)

    found = shutil.which("netbench")
    if found:
        return found

    return str(candidate)


def run_build(verbose: bool) -> None:
    cmd = ["cargo", "build", "--release"]
    eprint("build:", " ".join(cmd))
    subprocess.run(cmd, check=True, stdout=None if verbose else subprocess.DEVNULL)


def start_process(name: str, argv: List[str], env: Dict[str, str]) -> Proc:
    eprint(name + ":", " ".join(argv))
    p = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=None,
        env=env,
        text=True,
    )
    return Proc(name=name, popen=p)


def terminate_process(proc: Proc, timeout_s: float = 3.0) -> None:
    p = proc.popen
    if p.poll() is not None:
        return

    try:
        if is_windows():
            p.terminate()
        else:
            p.send_signal(signal.SIGTERM)
    except Exception:
        pass

    try:
        p.wait(timeout=timeout_s)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        if is_windows():
            p.kill()
        else:
            p.send_signal(signal.SIGKILL)
    except Exception:
        pass

    try:
        p.wait(timeout=timeout_s)
    except Exception:
        pass


def ensure_process_alive(proc: Proc) -> None:
    code = proc.popen.poll()
    if code is not None:
        raise RuntimeError(f"{proc.name} exited early with code {code}")


def wait_for_file(path: Path, timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if path.exists() and path.stat().st_size > 0:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for file: {path}")


def read_addr_file(path: Path, timeout_s: float = 10.0) -> str:
    wait_for_file(path, timeout_s=timeout_s)
    txt = path.read_text(encoding="utf-8").strip()
    if not txt:
        raise RuntimeError(f"address file empty: {path}")
    return txt


def parse_jsonl_lines(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def pick_summary_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if e.get("type") == "summary"]


def pick_final_event(events: Iterable[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    finals = [e for e in events if e.get("type") == "final"]
    return finals[-1] if finals else None


def safe_get(d: Dict[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def ascii_bar(value: float, max_value: float, width: int) -> str:
    if max_value <= 0:
        return " " * width
    ratio = max(0.0, min(1.0, value / max_value))
    n = int(round(ratio * width))
    return "█" * n + " " * (width - n)


def render_human_report(events: List[Dict[str, Any]]) -> None:
    summaries = pick_summary_events(events)
    final = pick_final_event(events)

    if not summaries and not final:
        print("no json summary lines captured")
        return

    print()
    print("netbench report")
    print()

    rows: List[Tuple[float, str, float, int, int, int]] = []
    for s in summaries:
        t_ms = float(s.get("t_ms", 0.0))
        t_s = t_ms / 1000.0
        phase = str(s.get("phase", ""))
        rps = float(s.get("rps", 0.0))

        ok = int(safe_get(s, "interval", "ok", default=0))
        conn = int(safe_get(s, "interval", "connect_fail", default=0))
        http = int(safe_get(s, "interval", "http_fail", default=0))
        rows.append((t_s, phase, rps, ok, conn, http))

    if rows:
        print("per second summary")
        print("time_s  phase    rps     ok  connect_fail  http_fail")
        for t_s, phase, rps, ok, conn, http in rows[-20:]:
            print(f"{t_s:6.1f}  {phase:6s}  {rps:6.1f}  {ok:5d}  {conn:12d}  {http:9d}")

        max_rps = max(r[2] for r in rows) if rows else 0.0
        print()
        print("rps graph")
        for t_s, phase, rps, ok, conn, http in rows[-40:]:
            bar = ascii_bar(rps, max_rps, width=32)
            print(f"{t_s:6.1f} {phase:6s} {rps:6.1f} {bar} ok={ok} cf={conn} hf={http}")

    if final:
        total = safe_get(final, "total", default={})
        total_total = int(safe_get(total, "total", default=0))
        total_ok = int(safe_get(total, "ok", default=0))
        total_conn = int(safe_get(total, "connect_fail", default=0))
        total_http = int(safe_get(total, "http_fail", default=0))
        total_other = int(safe_get(total, "other_fail", default=0))

        print()
        print("final totals")
        print(
            f"total={total_total} ok={total_ok} connect_fail={total_conn} "
            f"http_fail={total_http} other_fail={total_other}"
        )

        if total_total > 0:
            ok_rate = 100.0 * (total_ok / total_total)
            fail_rate = 100.0 * ((total_total - total_ok) / total_total)
            print(f"ok_rate={ok_rate:.2f}% fail_rate={fail_rate:.2f}%")
    print()


def render_diff_friendly_summary(events: List[Dict[str, Any]]) -> str:
    final = pick_final_event(events)
    if not final:
        return "no_final_event=1\n"

    total = safe_get(final, "total", default={})
    total_total = int(safe_get(total, "total", default=0))
    total_ok = int(safe_get(total, "ok", default=0))
    total_conn = int(safe_get(total, "connect_fail", default=0))
    total_http = int(safe_get(total, "http_fail", default=0))
    total_other = int(safe_get(total, "other_fail", default=0))

    lines = []
    lines.append(f"total={total_total}")
    lines.append(f"ok={total_ok}")
    lines.append(f"connect_fail={total_conn}")
    lines.append(f"http_fail={total_http}")
    lines.append(f"other_fail={total_other}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-proxy", action="store_true")
    ap.add_argument(
        "--scenario",
        default="baseline",
        choices=["baseline", "latency-jitter", "flaky-upstream"],
    )
    ap.add_argument(
        "--report-file", default=None, help="write JSONL report to file for diffing"
    )
    ap.add_argument("--verbose", action="store_true")

    args = ap.parse_args()

    run_build(verbose=args.verbose)
    netbench = netbench_path()

    data_dir = Path(tempfile.mkdtemp(prefix="safechain-netbench-"))
    eprint("data-dir:", str(data_dir))

    env = dict(os.environ)
    env.setdefault("RUST_LOG", "debug" if args.verbose else "info")

    procs: List[Proc] = []

    def cleanup() -> None:
        for pr in reversed(procs):
            terminate_process(pr)

        # Keep data dir if user asked for a report file, so artifacts remain inspectable.
        if args.report_file:
            return

        try:
            shutil.rmtree(data_dir)
        except Exception:
            pass

    atexit.register(cleanup)

    # Start mock server, let it bind to a free port and write address file.
    mock_argv = [
        netbench,
        "mock",
        "--scenario",
        args.scenario,
        "--data",
        str(data_dir),
    ]
    mock_proc = start_process("mock", mock_argv, env)
    procs.append(mock_proc)

    mock_addr_file = data_dir / "netbench.mock.addr.txt"
    mock_addr = read_addr_file(mock_addr_file, timeout_s=15.0)
    ensure_process_alive(mock_proc)
    eprint("mock addr:", mock_addr)

    # Start proxy optionally
    if args.with_proxy:
        proxy_argv = [
            netbench,
            "proxy",
            "--data",
            str(data_dir),
            mock_addr,
        ]
        proxy_proc = start_process("proxy", proxy_argv, env)
        procs.append(proxy_proc)

        proxy_addr_file = data_dir / "proxy.addr.txt"
        proxy_addr = read_addr_file(proxy_addr_file, timeout_s=15.0)
        ensure_process_alive(proxy_proc)
        eprint("proxy addr:", proxy_addr)
        target_addr = proxy_addr
    else:
        target_addr = mock_addr

    # Run benchmarker
    run_argv = [
        netbench,
        "run",
        "--json",
        "--scenario",
        args.scenario,
        "--data",
        str(data_dir),
    ]
    if args.with_proxy:
        run_argv.append("--proxy")
    run_argv.append(target_addr)

    eprint("run:", " ".join(run_argv))
    completed = subprocess.run(run_argv, env=env, capture_output=True, text=True)

    stdout_text = completed.stdout or ""
    stderr_text = completed.stderr or ""

    cleanup()

    if completed.returncode != 0:
        if stderr_text.strip():
            eprint(stderr_text.strip())
        raise RuntimeError(f"runner exited with code {completed.returncode}")

    events = parse_jsonl_lines(stdout_text)

    if args.report_file:
        report_path = Path(args.report_file)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(stdout_text, encoding="utf-8")

        summary_path = report_path.with_suffix(report_path.suffix + ".summary.txt")
        summary_path.write_text(render_diff_friendly_summary(events), encoding="utf-8")

        print(str(report_path))
        print(str(summary_path))
        print()
        print("diff friendly summary")
        print(summary_path.read_text(encoding="utf-8").strip())
        print()
        print("data-dir kept at")
        print(str(data_dir))
        return 0

    render_human_report(events)

    if stderr_text.strip():
        print("runner stderr")
        print(stderr_text.strip())
        print()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        eprint("error:", exc)
        raise SystemExit(1)
