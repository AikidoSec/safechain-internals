# Network Benchmarker (netbench)

`netbench` is a self-contained network benchmarking tool used to measure throughput, latency, error behavior, and regressions in HTTP-based systems.

It is designed to:
- generate realistic request traffic
- optionally run traffic through a local (safechain) proxy
- replay recorded traffic from HAR files (instead of generated mock data)
- produce machine-readable output for automation
- make performance regressions easy to spot over time

The project ships with:
- a **mock server** to simulate upstream behavior
- an optional **proxy** layer (~= safechain-proxy)
- a **benchmark runner**
- a small **orchestrator script** (`proxy_netbench/run.py`)
  to wire everything together and produce reports


## High-level overview

A typical benchmark run looks like this:

```

client traffic
↓
[ runner ] → (optional) → [ proxy ] → [ mock server ]

```

- The **runner** generates load and measures results
- The **mock server** simulates an upstream service
- The **proxy** allows measuring overhead, blocking behavior, or recording traffic
- All components are local and start automatically


## Output and artifacts

Each benchmark run creates a **temporary data directory** containing all artifacts for that run.

You will see paths like:

```
/tmp/safechain-netbench-xxxxxx/
├── netbench.mock.addr.txt
├── proxy.addr.txt              (only if proxy is used)
├── run.jsonl                   # raw JSON lines output from runner
├── run.summary.txt             # stable summary for diffing
└── logs/
    ├── mock.log
    ├── proxy.log               (only if proxy is used)
    └── run.log
````

### Important files

- **run.jsonl**
  - Machine-readable benchmark output
  - One JSON object per line
  - Safe to parse, archive, or feed into CI

- **run.summary.txt**
  - Stable key=value format
  - Designed for diffing between runs
  - Used for regression detection

- **logs/**
  - Full tracing output for debugging
  - Never printed to stdout by default

---

## Scenarios

Benchmarks are configured using **scenarios** instead of low-level tuning knobs.

Available scenarios:

| Scenario | Purpose |
|--------|--------|
| `baseline` | Ideal conditions. Measure pure overhead and regressions |
| `latency-jitter` | Variable latency. Observe queuing and tail behavior |
| `flaky-upstream` | Unstable upstream. Test error handling and resilience |

---

## Running benchmarks

The recommended way to run benchmarks is via the **orchestrator script**.

The script:
- builds `netbench` in release mode
- starts the mock server
- optionally starts the proxy
- runs the benchmark
- shows live progress
- produces human-readable and machine-readable output

### Basic run

```bash
just run-netbench
````

Uses:

* scenario: `baseline`
* direct connection to mock server
* live progress output
* final summary printed to console

---

### Run with a different scenario

```bash
just run-netbench --scenario latency-jitter
```

---

### Run through the proxy

```bash
just run-netbench --with-proxy
```

This measures the proxy overhead and behavior.

---

## Live feedback during runs

While the benchmark is running, you will see progress lines like:

```
[ 12.0s] phase=main   rps= 845.3 ok= 631 cf=0 hf=183 total_ok=12412 total_fail=3291
```

This shows:

* elapsed time
* current phase (warmup or main)
* requests per second
* success vs failure counts
* running totals

This makes it easy to see if a run is healthy or stalled.

---

## Saving results for regression tracking

### Save a baseline

```bash
just run-netbench \
  --scenario baseline \
  --save-baseline target/baselines/baseline.summary.txt
```

This creates a stable summary file that can be committed to git.

---

### Compare against a previous run

```bash
just run-netbench \
  --scenario baseline \
  --compare target/baselines/baseline.summary.txt
```

You will see a comparison section at the end:

```
comparison
avg_main_rps: 835.40 (+12.30, +1.5%)
ok_rate:      76.10% (-0.80pp)
total:        120000.00 (+0.00)
ok:           91320.00 (-960.00, -1.0%)
connect_fail: 0.00 (+0.00)
http_fail:    28680.00 (+960.00, +3.5%)
```

---

### Store full reports

```bash
just run-netbench \
  --with-proxy \
  --scenario baseline \
  --report-file target/reports/baseline_proxy.jsonl
```

This writes:

* raw JSONL report
* stable summary file next to it
* keeps the full data directory for inspection

## Direct CLI usage (advanced)

The orchestrator is recommended, but the individual components can be run manually.

### Mock server

```bash
netbench mock --scenario baseline

# use `netbench mock --help` for more usage info
```

### Proxy

```bash
netbench proxy <mock-address>

# use `netbench proxy --help` for more usage info
```

### Runner

```bash
netbench run --json --scenario baseline <address>

# use `netbench run --help` for more usage info
```

Manual usage is useful for debugging or integration with custom tooling.
