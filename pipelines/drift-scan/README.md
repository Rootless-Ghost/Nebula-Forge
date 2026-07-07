# drift-scan

**drift-scan** normalizes a batch of raw log events, pulls your current Sigma rule set, and runs DriftWatch analysis to surface which rules have coverage and which have drifted out of alignment with live data.

```
Raw logs (file or directory: .json / .log)
    ↓
LogNorm            POST /api/normalize/batch
(→ ECS-lite normalized events)
    ↓
SigmaForge         GET /api/rules
(current Sigma rule set)
    ↓
DriftWatch         POST /api/analyze
(coverage gaps, stale/missing detections, time_window_hours)
    ↓
output/drift_scan_{timestamp}.json
```

## How it works

1. **Load.** `--input` may be a single file or a directory. If it's a directory, every `.json`/`.log` file in it is read (sorted by name). Each file may be a raw JSON list of events, a dict wrapper (`{"events": [...]}` or `{"logs": [...]}`), or a single event dict. If nothing loads, drift-scan exits with an error.
2. **Normalize.** All loaded events are serialized as NDJSON and POSTed to LogNorm's `/api/normalize/batch` along with `--source` as `source_type`, producing ECS-lite normalized events.
3. **Fetch rules.** drift-scan `GET`s SigmaForge's `/api/rules` for the current rule set. The response can be a raw list or `{"rules": [...]}`; individual rules can be strings or dicts with a `content`/`yaml` field.
4. **Analyze.** Normalized events + fetched rules + `--window` (hours) are POSTed to DriftWatch's `/api/analyze`, which reports rule coverage and gaps.
5. **Report.** Raw event count, normalized event count, rule count, and the full drift analysis are written to a timestamped JSON report, with a summary printed to stdout.

## Graceful degradation

drift-scan is built to keep going when a dependency is down, rather than fail the whole run:

- **LogNorm unreachable** → falls back to using the *raw* (un-normalized) events for the rest of the pipeline; logs a warning.
- **SigmaForge unreachable** → proceeds with an empty rule list.
- **No rules available** (empty from SigmaForge, or none fetched) → DriftWatch analysis is skipped entirely with a warning; the report still gets written.
- **DriftWatch unreachable** → analysis is skipped with a warning; the report still gets written.
- **`--dry-run`** → always skips DriftWatch analysis, regardless of rule availability (normalize + fetch still happen).

---

## Architecture

```
pipelines/drift-scan/
├── main.py       # Entry point — CLI, HTTP orchestration, reporting
└── output/       # JSON reports (created at runtime)
```

No `requirements.txt` — drift-scan uses only the Python standard library (`argparse`, `json`, `logging`, `os`, `sys`, `urllib.request`/`urllib.error`, `datetime`).

### Pipeline stages

| Stage | Function | What it does |
|---|---|---|
| **Load** | `load_events()` | Reads events from a file or directory of `.json`/`.log` files; unwraps `events`/`logs` dict keys or list-of-events. |
| **Normalize** | `normalize_events()` | `POST` LogNorm `/api/normalize/batch` with `source_type` + NDJSON `raw`; falls back to raw events on failure. |
| **Fetch rules** | `fetch_sigma_rules()` | `GET` SigmaForge `/api/rules`; returns `[]` on failure. |
| **Analyze** | `run_driftwatch()` | `POST` DriftWatch `/api/analyze` with events, rules, `time_window_hours`; skipped if no rules. |
| **Report** | `save_report()` | Writes `drift_scan_{timestamp}.json` to `output_dir` with event/rule counts and the drift analysis result. |

---

## Setup

### Prerequisites

| Service | Default URL |
|---|---|
| LogNorm | `http://127.0.0.1:5006` |
| SigmaForge | `http://127.0.0.1:5000` |
| DriftWatch | `http://127.0.0.1:5008` |

Override any of these per-run with `--lognorm-url`, `--sigmaforge-url`, `--driftwatch-url`.

---

## Usage

### Scan a log file

```bash
python main.py --input /path/to/events.json --source sysmon
```

### Scan a directory (all `.json`/`.log` files)

```bash
python main.py --input /path/to/logs/ --source wel
```

### Set a look-back window and save the report

```bash
python main.py --input /path/to/events.json --source sysmon --window 168
```

### Dry run (normalize only, skip DriftWatch)

```bash
python main.py --input /path/to/events.json --dry-run
```

### All flags

| Flag | Default | Meaning |
|---|---|---|
| `--input` | *(required)* | Log file or directory path |
| `--source` | `sysmon` | One of `sysmon`, `wel`, `wazuh`, `syslog`, `cef` |
| `--window` | `168` | Look-back window in hours for DriftWatch |
| `--output` | `./output` | Report output directory |
| `--lognorm-url` | `http://127.0.0.1:5006` | LogNorm base URL |
| `--sigmaforge-url` | `http://127.0.0.1:5000` | SigmaForge base URL |
| `--driftwatch-url` | `http://127.0.0.1:5008` | DriftWatch base URL |
| `--timeout` | `30` | HTTP timeout (seconds) |
| `--dry-run` | off | Normalize only — skip DriftWatch analysis |
| `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Output

Each run writes one JSON report to `output_dir` (default `./output`):

```
drift_scan_{timestamp}.json
```

containing `scan_id`, `timestamp`, `input_path`, `source`, `window_hours`, `raw_event_count`, `norm_event_count`, `rule_count`, and `drift_analysis`.

A summary is also printed to stdout: raw/normalized event counts, rules fetched, and (if analysis ran) rules with gaps and coverage counts.

---

## License

This project is licensed under the MIT License — see the root [LICENSE](../../LICENSE) file for details.
