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
from typing import Any, Dict, List, Optional, Tuple


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
    p = subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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
        try:
            if path.exists() and path.stat().st_size > 0:
                return
        except FileNotFoundError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"timeout waiting for file: {path}")


def read_addr_file(path: Path, timeout_s: float = 10.0) -> str:
    wait_for_file(path, timeout_s=timeout_s)
    txt = path.read_text(encoding="utf-8").strip()
    if not txt:
        raise RuntimeError(f"address file empty: {path}")
    return txt


def parse_json_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def safe_get(d: Dict[str, Any], *path: str, default: Any = None) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def render_diff_friendly_summary_from_events(events: List[Dict[str, Any]]) -> str:
    finals = [e for e in events if e.get("type") == "final"]
    final = finals[-1] if finals else None
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


def ascii_bar(value: float, max_value: float, width: int) -> str:
    if max_value <= 0:
        return " " * width
    ratio = max(0.0, min(1.0, value / max_value))
    n = int(round(ratio * width))
    return "█" * n + " " * (width - n)


def print_runner_progress_spinner(
    start_ts: float,
    last_summary: Optional[Dict[str, Any]],
    spin_state: int,
) -> int:
    spinner = ["|", "/", "-", "\\"]
    ch = spinner[spin_state % len(spinner)]
    elapsed = time.time() - start_ts

    if last_summary:
        phase = str(last_summary.get("phase", ""))
        rps = float(last_summary.get("rps", 0.0))
        ok = int(safe_get(last_summary, "interval", "ok", default=0))
        cf = int(safe_get(last_summary, "interval", "connect_fail", default=0))
        hf = int(safe_get(last_summary, "interval", "http_fail", default=0))
        msg = (
            f"{ch} {elapsed:6.1f}s phase={phase} rps={rps:6.1f} ok={ok} cf={cf} hf={hf}"
        )
    else:
        msg = f"{ch} {elapsed:6.1f}s running"

    sys.stderr.write("\r" + msg + " " * 10)
    sys.stderr.flush()
    return spin_state + 1


def finalize_spinner_line() -> None:
    sys.stderr.write("\r" + " " * 120 + "\r")
    sys.stderr.flush()


def format_summary_line(s: Dict[str, Any], elapsed_wall_s: float) -> str:
    phase = str(s.get("phase", ""))
    rps = float(s.get("rps", 0.0))
    ok = int(safe_get(s, "interval", "ok", default=0))
    cf = int(safe_get(s, "interval", "connect_fail", default=0))
    hf = int(safe_get(s, "interval", "http_fail", default=0))

    tot_ok = int(safe_get(s, "total", "ok", default=0))
    tot_total = int(safe_get(s, "total", "total", default=0))
    tot_fail = tot_total - tot_ok if tot_total >= tot_ok else 0

    t_ms = float(s.get("t_ms", 0.0))
    t_s = t_ms / 1000.0 if t_ms > 0 else elapsed_wall_s

    return (
        f"[{t_s:6.1f}s] phase={phase:6s} "
        f"rps={rps:7.1f} ok={ok:5d} cf={cf:4d} hf={hf:4d} "
        f"total_ok={tot_ok} total_fail={tot_fail}"
    )


def print_progress_line(s: Dict[str, Any], start_ts: float) -> None:
    elapsed = time.time() - start_ts
    eprint(format_summary_line(s, elapsed))


def compute_aggregate_from_events(events: List[Dict[str, Any]]) -> Dict[str, float]:
    final = next((e for e in reversed(events) if e.get("type") == "final"), None)

    total_total = float(safe_get(final or {}, "total", "total", default=0))
    total_ok = float(safe_get(final or {}, "total", "ok", default=0))
    connect_fail = float(safe_get(final or {}, "total", "connect_fail", default=0))
    http_fail = float(safe_get(final or {}, "total", "http_fail", default=0))
    other_fail = float(safe_get(final or {}, "total", "other_fail", default=0))

    ok_rate = (total_ok / total_total) if total_total > 0 else 0.0

    summaries = [
        e for e in events if e.get("type") == "summary" and e.get("phase") == "main"
    ]
    if summaries:
        avg_rps = sum(float(s.get("rps", 0.0)) for s in summaries) / float(
            len(summaries)
        )
    else:
        avg_rps = 0.0

    return {
        "avg_main_rps": avg_rps,
        "total": total_total,
        "ok": total_ok,
        "connect_fail": connect_fail,
        "http_fail": http_fail,
        "other_fail": other_fail,
        "ok_rate": ok_rate,
    }


def write_kv_baseline(path: Path, metrics: Dict[str, float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"avg_main_rps={metrics.get('avg_main_rps', 0.0)}",
        f"total={metrics.get('total', 0.0)}",
        f"ok={metrics.get('ok', 0.0)}",
        f"connect_fail={metrics.get('connect_fail', 0.0)}",
        f"http_fail={metrics.get('http_fail', 0.0)}",
        f"other_fail={metrics.get('other_fail', 0.0)}",
        f"ok_rate={metrics.get('ok_rate', 0.0)}",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_kv_summary(text: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        try:
            out[k] = float(v)
        except ValueError:
            continue
    return out


def load_metrics_from_path(path: Path) -> Dict[str, float]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower().endswith("jsonl"):
        events: List[Dict[str, Any]] = []
        for line in text.splitlines():
            ev = parse_json_line(line)
            if ev is not None:
                events.append(ev)
        return compute_aggregate_from_events(events)

    return parse_kv_summary(text)


def format_delta(cur: float, prev: float, is_rate: bool = False) -> str:
    d = cur - prev
    if is_rate:
        return f"{cur * 100:.2f}% ({d * 100:+.2f}pp)"
    if prev != 0:
        pct = (d / prev) * 100.0
        return f"{cur:.2f} ({d:+.2f}, {pct:+.1f}%)"
    return f"{cur:.2f} ({d:+.2f})"


def print_comparison_section(
    current: Dict[str, float], previous: Dict[str, float]
) -> None:
    print()
    print("comparison")
    print(
        f"avg_main_rps: {format_delta(current.get('avg_main_rps', 0.0), previous.get('avg_main_rps', 0.0))}"
    )
    print(
        f"ok_rate:      {format_delta(current.get('ok_rate', 0.0), previous.get('ok_rate', 0.0), is_rate=True)}"
    )
    print(
        f"total:        {format_delta(current.get('total', 0.0), previous.get('total', 0.0))}"
    )
    print(
        f"ok:           {format_delta(current.get('ok', 0.0), previous.get('ok', 0.0))}"
    )
    print(
        f"connect_fail: {format_delta(current.get('connect_fail', 0.0), previous.get('connect_fail', 0.0))}"
    )
    print(
        f"http_fail:    {format_delta(current.get('http_fail', 0.0), previous.get('http_fail', 0.0))}"
    )
    print(
        f"other_fail:   {format_delta(current.get('other_fail', 0.0), previous.get('other_fail', 0.0))}"
    )
    print()


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
    ap.add_argument(
        "--compare",
        default=None,
        help="path to previous summary.txt or jsonl for comparison",
    )
    ap.add_argument(
        "--save-baseline",
        default=None,
        help="write current baseline summary (kv) to this path",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    run_build(verbose=args.verbose)
    netbench = netbench_path()

    data_dir = Path(tempfile.mkdtemp(prefix="safechain-netbench-"))
    logs_dir = data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    mock_log = logs_dir / "mock.log"
    proxy_log = logs_dir / "proxy.log"
    run_log = logs_dir / "run.log"

    run_jsonl = data_dir / "run.jsonl"
    run_summary = data_dir / "run.summary.txt"

    env = dict(os.environ)
    env.setdefault("RUST_LOG", "debug" if args.verbose else "info")

    procs: List[Proc] = []
    keep_data = bool(args.report_file)

    def cleanup(keep: bool) -> None:
        for pr in reversed(procs):
            terminate_process(pr)

        if keep:
            return

        try:
            shutil.rmtree(data_dir)
        except Exception:
            pass

    atexit.register(lambda: cleanup(keep_data))

    # Start mock server, traces to file
    eprint("mock: starting")
    mock_argv = [
        netbench,
        "mock",
        "--scenario",
        args.scenario,
        "--data",
        str(data_dir),
        "--output",
        str(mock_log),
    ]
    mock_proc = start_process("mock", mock_argv, env)
    procs.append(mock_proc)

    mock_addr_file = data_dir / "netbench.mock.addr.txt"
    eprint("mock: waiting for address file")
    mock_addr = read_addr_file(mock_addr_file, timeout_s=20.0)
    ensure_process_alive(mock_proc)
    eprint("mock:", mock_addr)

    # Start proxy optionally, traces to file
    if args.with_proxy:
        eprint("proxy: starting")
        proxy_argv = [
            netbench,
            "proxy",
            "--data",
            str(data_dir),
            "--output",
            str(proxy_log),
            mock_addr,
        ]
        proxy_proc = start_process("proxy", proxy_argv, env)
        procs.append(proxy_proc)

        proxy_addr_file = data_dir / "proxy.addr.txt"
        eprint("proxy: waiting for address file")
        proxy_addr = read_addr_file(proxy_addr_file, timeout_s=20.0)
        ensure_process_alive(proxy_proc)
        eprint("proxy:", proxy_addr)
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
        "--output",
        str(run_log),
    ]
    if args.with_proxy:
        run_argv.append("--proxy")
    run_argv.append(target_addr)

    eprint("run: started")
    runner = subprocess.Popen(
        run_argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    events: List[Dict[str, Any]] = []
    last_summary: Optional[Dict[str, Any]] = None
    start_ts = time.time()
    spin = 0

    with run_jsonl.open("w", encoding="utf-8") as f_jsonl:
        assert runner.stdout is not None

        last_spin_update = 0.0
        while True:
            line = runner.stdout.readline()
            if line:
                f_jsonl.write(line)
                f_jsonl.flush()

                ev = parse_json_line(line)
                if ev is not None:
                    events.append(ev)
                    if ev.get("type") == "summary":
                        last_summary = ev
                        print_progress_line(ev, start_ts)
            else:
                code = runner.poll()
                now = time.time()

                if now - last_spin_update >= 0.15:
                    spin = print_runner_progress_spinner(start_ts, last_summary, spin)
                    last_spin_update = now

                if code is not None:
                    break

                time.sleep(0.03)

    finalize_spinner_line()

    rc = runner.wait()
    if rc != 0:
        cleanup(keep=True)
        raise RuntimeError(
            "runner failed. Logs and artifacts:\n"
            f"- data dir: {data_dir}\n"
            f"- jsonl: {run_jsonl}\n"
            f"- mock log: {mock_log}\n"
            f"- proxy log: {proxy_log if args.with_proxy else '(no proxy)'}\n"
            f"- run log: {run_log}\n"
        )

    # Always write stable summary to data dir
    run_summary.write_text(
        render_diff_friendly_summary_from_events(events), encoding="utf-8"
    )

    # Compute metrics for comparison and saving
    current_metrics = compute_aggregate_from_events(events)

    if args.save_baseline:
        write_kv_baseline(Path(args.save_baseline), current_metrics)

    # Stop services
    cleanup(keep=keep_data)

    # Copy report artifacts if requested
    if args.report_file:
        report_path = Path(args.report_file)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(run_jsonl.read_text(encoding="utf-8"), encoding="utf-8")

        summary_path = report_path.with_suffix(report_path.suffix + ".summary.txt")
        summary_path.write_text(
            run_summary.read_text(encoding="utf-8"), encoding="utf-8"
        )

        print(str(report_path))
        print(str(summary_path))
        print()
        print("diff friendly summary")
        print(summary_path.read_text(encoding="utf-8").strip())

        # Optional compare output even in report mode
        if args.compare:
            previous_metrics = load_metrics_from_path(Path(args.compare))
            print_comparison_section(current_metrics, previous_metrics)

        print()
        print("logs")
        print(str(mock_log))
        if args.with_proxy:
            print(str(proxy_log))
        print(str(run_log))
        return 0

    # Human output
    print()
    print("netbench finished")
    print(f"scenario={args.scenario} proxied={'yes' if args.with_proxy else 'no'}")
    print()

    summaries = [e for e in events if e.get("type") == "summary"]
    if summaries:
        rows: List[Tuple[float, str, float, int, int, int]] = []
        for s in summaries:
            t_ms = float(s.get("t_ms", 0.0))
            t_s = t_ms / 1000.0
            phase = str(s.get("phase", ""))
            rps = float(s.get("rps", 0.0))
            ok = int(safe_get(s, "interval", "ok", default=0))
            cf = int(safe_get(s, "interval", "connect_fail", default=0))
            hf = int(safe_get(s, "interval", "http_fail", default=0))
            rows.append((t_s, phase, rps, ok, cf, hf))

        print("per second summary (last 12)")
        print("time_s  phase    rps     ok  connect_fail  http_fail")
        for t_s, phase, rps, ok, cf, hf in rows[-12:]:
            print(f"{t_s:6.1f}  {phase:6s}  {rps:6.1f}  {ok:5d}  {cf:12d}  {hf:9d}")

        max_rps = max(r[2] for r in rows) if rows else 0.0
        print()
        print("rps graph (last 24)")
        for t_s, phase, rps, ok, cf, hf in rows[-24:]:
            bar = ascii_bar(rps, max_rps, width=24)
            print(f"{t_s:6.1f} {phase:6s} {rps:6.1f} {bar} ok={ok} cf={cf} hf={hf}")
        print()

    final = next((e for e in reversed(events) if e.get("type") == "final"), None)
    if final:
        total = safe_get(final, "total", default={})
        total_total = int(safe_get(total, "total", default=0))
        total_ok = int(safe_get(total, "ok", default=0))
        total_cf = int(safe_get(total, "connect_fail", default=0))
        total_hf = int(safe_get(total, "http_fail", default=0))
        total_of = int(safe_get(total, "other_fail", default=0))
        print("final totals")
        print(
            f"total={total_total} ok={total_ok} connect_fail={total_cf} http_fail={total_hf} other_fail={total_of}"
        )
        print()

    if args.compare:
        previous_metrics = load_metrics_from_path(Path(args.compare))
        print_comparison_section(current_metrics, previous_metrics)

    print("artifacts")
    print(f"data dir: {data_dir}")
    print(f"jsonl: {run_jsonl}")
    print(f"summary: {run_summary}")
    print(f"mock log: {mock_log}")
    if args.with_proxy:
        print(f"proxy log: {proxy_log}")
    print(f"run log: {run_log}")
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
