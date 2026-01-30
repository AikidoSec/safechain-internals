#!/usr/bin/env python3

from __future__ import annotations

import argparse
import atexit
import http.client
import json
import os
import shutil
import signal
import socket
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
    def read_totals_from_container(container: Any) -> Optional[Dict[str, int]]:
        if not isinstance(container, dict):
            return None

        # Most common: {"total": {...}}
        t = container.get("total")
        if isinstance(t, dict):
            return {
                "total": int(t.get("total", 0)),
                "ok": int(t.get("ok", 0)),
                "http_fail": int(t.get("http_fail", 0)),
                "other_fail": int(t.get("other_fail", 0)),
            }

        # Alternate: totals are flat on the event itself
        if "total" in container or "ok" in container:
            return {
                "total": int(container.get("total", 0)),
                "ok": int(container.get("ok", 0)),
                "http_fail": int(container.get("http_fail", 0)),
                "other_fail": int(container.get("other_fail", 0)),
            }

        return None

    # 1) Prefer final event totals
    final = next((e for e in reversed(events) if e.get("type") == "final"), None)
    totals = read_totals_from_container(final)

    # 2) Fallback to last summary totals
    if totals is None:
        last_summary = next(
            (e for e in reversed(events) if e.get("type") == "summary"), None
        )
        totals = read_totals_from_container(last_summary)

    # 3) Last resort: sum interval counters across all summaries
    if totals is None:
        total_total = 0
        total_ok = 0
        total_http = 0
        total_other = 0

        for e in events:
            if e.get("type") != "summary":
                continue
            interval = e.get("interval")
            if not isinstance(interval, dict):
                continue

            total_total += int(interval.get("total", 0))
            total_ok += int(interval.get("ok", 0))
            total_http += int(interval.get("http_fail", 0))
            total_other += int(interval.get("other_fail", 0))

        totals = {
            "total": total_total,
            "ok": total_ok,
            "http_fail": total_http,
            "other_fail": total_other,
        }

    lines = []
    lines.append(f"total={totals['total']}")
    lines.append(f"ok={totals['ok']}")
    lines.append(f"http_fail={totals['http_fail']}")
    lines.append(f"other_fail={totals['other_fail']}")
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
        hf = int(safe_get(last_summary, "interval", "http_fail", default=0))
        msg = f"{ch} {elapsed:6.1f}s phase={phase} rps={rps:6.1f} ok={ok} hf={hf}"
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
    hf = int(safe_get(s, "interval", "http_fail", default=0))

    tot_ok = int(safe_get(s, "total", "ok", default=0))
    tot_total = int(safe_get(s, "total", "total", default=0))
    tot_fail = tot_total - tot_ok if tot_total >= tot_ok else 0

    t_ms = float(s.get("t_ms", 0.0))
    t_s = t_ms / 1000.0 if t_ms > 0 else elapsed_wall_s

    return (
        f"[{t_s:6.1f}s] phase={phase:6s} "
        f"rps={rps:7.1f} ok={ok:5d} hf={hf:4d} "
        f"total_ok={tot_ok} total_fail={tot_fail}"
    )


def print_progress_line(s: Dict[str, Any], start_ts: float) -> None:
    elapsed = time.time() - start_ts
    eprint(format_summary_line(s, elapsed))


def compute_aggregate_from_events(events: List[Dict[str, Any]]) -> Dict[str, float]:
    final = next((e for e in reversed(events) if e.get("type") == "final"), None)

    totals_src: Optional[Dict[str, Any]] = None

    if isinstance(final, dict):
        t = final.get("total")
        if isinstance(t, dict) and ("total" in t or "ok" in t):
            totals_src = t

    if totals_src is None:
        last_summary = next(
            (e for e in reversed(events) if e.get("type") == "summary"), None
        )
        if isinstance(last_summary, dict):
            t = last_summary.get("total")
            if isinstance(t, dict) and ("total" in t or "ok" in t):
                totals_src = t

    if totals_src is None:
        total_total = 0.0
        total_ok = 0.0
        http_fail = 0.0
        other_fail = 0.0
    else:
        total_total = float(totals_src.get("total", 0.0))
        total_ok = float(totals_src.get("ok", 0.0))
        http_fail = float(totals_src.get("http_fail", 0.0))
        other_fail = float(totals_src.get("other_fail", 0.0))

    ok_rate = (total_ok / total_total) if total_total > 0 else 0.0

    main_summaries = [
        e for e in events if e.get("type") == "summary" and e.get("phase") == "main"
    ]
    if main_summaries:
        avg_rps = sum(float(s.get("rps", 0.0)) for s in main_summaries) / float(
            len(main_summaries)
        )
    else:
        avg_rps = 0.0

    return {
        "avg_main_rps": avg_rps,
        "total": total_total,
        "ok": total_ok,
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


def split_host_port(addr: str) -> Tuple[str, int]:
    # addr looks like "127.0.0.1:57777"
    host, port_s = addr.rsplit(":", 1)
    return host, int(port_s)


def fetch_blocked_events_count_via_mock(
    mock_addr: str, timeout_s: float = 2.0
) -> Optional[int]:
    """
    Query the mock server for blocked event count.

    The endpoint is served by the mock server under a pseudo domain:
    GET https://reporter-fake-aikido.internal/counter/blocked-events

    We connect to the mock server socket address, but we send Host header
    for reporter-fake-aikido.internal so the mock server routes it correctly.
    """
    host, port = split_host_port(mock_addr)

    conn = http.client.HTTPConnection(host, port, timeout=timeout_s)
    try:
        conn.request(
            "GET",
            "/reporter/counter/blocked-events",
            headers={
                "Host": "localhost",
                "Accept": "text/plain",
                "Connection": "close",
            },
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace").strip()

        if resp.status < 200 or resp.status >= 300:
            eprint("blocked-events: unexpected status", resp.status, body[:200])
            return None

        try:
            return int(body)
        except ValueError:
            eprint("blocked-events: non-int payload", body[:200])
            return None
    except (OSError, http.client.HTTPException, socket.timeout) as exc:
        eprint("blocked-events: request failed", exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


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
        f"http_fail:    {format_delta(current.get('http_fail', 0.0), previous.get('http_fail', 0.0))}"
    )
    print(
        f"other_fail:   {format_delta(current.get('other_fail', 0.0), previous.get('other_fail', 0.0))}"
    )
    print()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--proxy",
        default="direct",
        choices=["direct", "global", "scoped"],
        help="global vs scoped only has impact on mock (gen) data",
    )
    ap.add_argument(
        "--scenario",
        default="baseline",
        choices=["baseline", "latency-jitter", "flaky-upstream"],
        help="ignored when --har is set",
    )
    ap.add_argument("--har", default=None, help="replay requests from this HAR file")
    ap.add_argument(
        "--emulate",
        action="store_true",
        help="when replaying, also emulate recorded timings",
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

    har_path: Optional[Path] = (
        Path(args.har).expanduser().resolve() if args.har else None
    )
    if har_path is not None and not har_path.exists():
        raise RuntimeError(f"har file not found: {har_path}")

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
    env.setdefault("RUST_LOG", "trace" if args.verbose else "info")

    procs: List[Proc] = []
    keep_data = bool(args.report_file)

    proxy_is_enabled = args.proxy and args.proxy != "direct"

    def cleanup(keep: bool) -> None:
        for pr in reversed(procs):
            terminate_process(pr)

        if keep:
            return

    atexit.register(lambda: cleanup(keep_data))

    # Start mock server
    eprint("mock: starting")
    mock_argv = [
        netbench,
        "mock",
        "--data",
        str(data_dir),
        "--output",
        str(mock_log),
    ]
    if har_path is not None:
        # HAR mode: replay responses from the HAR
        mock_argv += ["--replay", str(har_path)]
    else:
        # Normal mode: use scenario behavior
        mock_argv += ["--scenario", args.scenario]

    mock_proc = start_process("mock", mock_argv, env)
    procs.append(mock_proc)

    mock_addr_file = data_dir / "netbench.mock.addr.txt"
    eprint("mock: waiting for address file")
    mock_addr = read_addr_file(mock_addr_file, timeout_s=20.0)
    ensure_process_alive(mock_proc)
    eprint("mock:", mock_addr)

    # Start proxy optionally
    if proxy_is_enabled:
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
        "--data",
        str(data_dir),
        "--output",
        str(run_log),
    ]

    if har_path is not None:
        run_argv += ["--replay", str(har_path)]
        if args.emulate:
            run_argv.append("--emulate")
    else:
        run_argv += ["--scenario", args.scenario]

    if proxy_is_enabled:
        run_argv.append("--proxy")
        if args.proxy == "global":
            run_argv += ["--products", "none, vscode; q=0.2, pypi; q=0.1"]
        elif args.proxy == "scoped":
            run_argv += ["--products", "vscode; q=0.6, pypi; q=0.4"]

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
            f"- proxy log: {proxy_log if args.proxy else '(no proxy)'}\n"
            f"- run log: {run_log}\n"
        )

    # Always write stable summary to data dir
    run_summary.write_text(
        render_diff_friendly_summary_from_events(events), encoding="utf-8"
    )

    # Compute metrics for comparison and saving
    current_metrics = compute_aggregate_from_events(events)

    blocked_count: Optional[int] = None
    if proxy_is_enabled:
        blocked_count = fetch_blocked_events_count_via_mock(mock_addr)
        if blocked_count is not None:
            eprint(f"proxy: blocked_events_total={blocked_count}")
        else:
            eprint("proxy: blocked_events_total=unknown")

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

        if args.compare:
            previous_metrics = load_metrics_from_path(Path(args.compare))
            print_comparison_section(current_metrics, previous_metrics)

        print()
        print("logs")
        print(str(mock_log))
        if args.proxy_enabled:
            print(str(proxy_log))
        print(str(run_log))

        if proxy_is_enabled:
            if blocked_count is not None:
                print()
                print(f"blocked_events_total={blocked_count}")
            else:
                print()
                print("blocked_events_total=unknown")

        return 0

    # Human output
    print()
    print("netbench finished")
    if har_path is not None:
        print(
            f"mode=har har={har_path} emulate={'yes' if args.emulate else 'no'} proxy={args.proxy}"
        )
        if proxy_is_enabled:
            if blocked_count is not None:
                print(f"blocked_events_total={blocked_count}")
            else:
                print("blocked_events_total=unknown")
            print()
    else:
        print(f"mode=scenario scenario={args.scenario} proxied={args.proxy}")
    print()

    summaries = [e for e in events if e.get("type") == "summary"]
    if summaries:
        rows: List[Tuple[float, str, float, int, int]] = []
        for s in summaries:
            t_ms = float(s.get("t_ms", 0.0))
            t_s = t_ms / 1000.0
            phase = str(s.get("phase", ""))
            rps = float(s.get("rps", 0.0))
            ok = int(safe_get(s, "interval", "ok", default=0))
            hf = int(safe_get(s, "interval", "http_fail", default=0))
            rows.append((t_s, phase, rps, ok, hf))

        print("per second summary (last 12)")
        print("time_s  phase    rps     ok  http_fail")
        for t_s, phase, rps, ok, hf in rows[-12:]:
            print(f"{t_s:6.1f}  {phase:6s}  {rps:6.1f}  {ok:5d}  {hf:9d}")

        max_rps = max(r[2] for r in rows) if rows else 0.0
        print()
        print("rps graph (last 24)")
        for t_s, phase, rps, ok, hf in rows[-24:]:
            bar = ascii_bar(rps, max_rps, width=24)
            print(f"{t_s:6.1f} {phase:6s} {rps:6.1f} {bar} ok={ok} hf={hf}")
        print()

    final = next((e for e in reversed(events) if e.get("type") == "final"), None)
    if final:
        total = safe_get(final, "total", default={})
        total_total = int(safe_get(total, "total", default=0))
        total_ok = int(safe_get(total, "ok", default=0))
        total_hf = int(safe_get(total, "http_fail", default=0))
        total_of = int(safe_get(total, "other_fail", default=0))
        print("final totals")
        print(
            f"total={total_total} ok={total_ok} http_fail={total_hf} other_fail={total_of}"
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
    if proxy_is_enabled:
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
