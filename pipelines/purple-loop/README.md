# purple-loop

**purple-loop** is a safety-gated adversary simulation pipeline: give it a MITRE ATT&CK technique ID, and it generates hunt context, executes the atomic test, and validates whether your Sigma detection actually fires against the resulting events.

```
ATT&CK technique ID (e.g. T1059.001)
    ↓
HuntForge          POST /api/playbook/generate
(hunt context + starter Sigma rule)
    ↓
AtomicLoop         POST /api/run
(execute atomic test — confirm/dry-run gated — capture + normalize events)
    ↓
AtomicLoop /api/validate  (proxies to DriftWatch, if run_id present)
   — or DriftWatch POST /api/validate directly, as a fallback —
(Sigma rule: fired / missed + gap analysis)
    ↓
output/purple_loop_{technique}_test{N}_{timestamp}.json
```

## How it works

1. **Hunt context.** Unless you supply your own rule with `--sigma`, purple-loop asks HuntForge (`POST /api/playbook/generate`) for a hunt playbook for the given technique and pulls the Sigma rule out of `queries.sigma` (falling back to `playbook.queries.sigma`). If HuntForge is unreachable, this step is skipped — non-fatal — and the run continues without a rule.
2. **Execute.** The technique is run through AtomicLoop (`POST /api/run`) with `capture_events=True` and `normalize=True`, so AtomicLoop both runs the atomic test and captures the resulting Windows events. `--test`, `--arg KEY=VALUE`, and `--exec-timeout` all flow into this request.
3. **Validate.** If a Sigma rule and a run result are both available, purple-loop checks whether the rule actually detects what just happened. If the run has a `run_id`, it calls AtomicLoop's `/api/validate`, which proxies through DriftWatch server-side. If there's no `run_id`, it falls back to calling DriftWatch's `/api/validate` directly with the raw rule YAML and captured events.
4. **Report.** Everything — the playbook, the Sigma rule, the atomic run result, and the validation result — is written to a single timestamped JSON report, and a human-readable summary (mode, exit code, event count, fired/missed, gap analysis) is printed to stdout.

## Safety model

Live execution against a real endpoint is opt-in, not default:

- **`--dry-run`** previews the command purple-loop would run — always safe, no execution.
- **`--confirm`** is *required* for live execution. If you pass neither flag, purple-loop exits immediately with an error rather than guessing your intent.

This makes purple-loop safe to wire into CI or hand to someone unfamiliar with the tool — nothing executes on a host without an explicit `--confirm`.

---

## Architecture

```
pipelines/purple-loop/
├── main.py       # Entry point — CLI, HTTP orchestration, reporting
└── output/       # JSON reports (created at runtime)
```

No `requirements.txt` — purple-loop uses only the Python standard library (`argparse`, `json`, `logging`, `os`, `sys`, `urllib.request`/`urllib.error`, `datetime`).

### Pipeline stages

| Stage | Function | What it does |
|---|---|---|
| **Hunt context** | `get_huntforge_context()` | `POST` HuntForge `/api/playbook/generate`; extracts the Sigma rule from `queries.sigma` (or `playbook.queries.sigma`). Skipped if `--sigma` is given. Failure is logged and non-fatal. |
| **Execute** | `run_atomic_test()` | `POST` AtomicLoop `/api/run` with `technique_id`, `test_number`, `confirm`, `dry_run`, `capture_events=True`, `normalize=True`, `input_arguments`, `timeout`. Sends `X-API-Key` header if `ATOMICLOOP_API_KEY` is set. |
| **Validate** | `validate_with_driftwatch()` | Runs only if a Sigma rule *and* a run result exist. Prefers AtomicLoop `/api/validate` (proxies to DriftWatch, keyed by `run_id`); falls back to calling DriftWatch `/api/validate` directly with `rules_yaml` + `events_json` + `time_window_hours=1`. |
| **Report** | `save_report()` | Writes `purple_loop_{technique}_test{N}_{timestamp}.json` to `output_dir` containing `detection_fired`, the HuntForge playbook, the Sigma rule, the atomic run result, and the validation result. |

---

## Setup

### Prerequisites

All three services must be running:

| Service | Default URL |
|---|---|
| HuntForge | `http://127.0.0.1:5007` |
| AtomicLoop | `http://127.0.0.1:5011` |
| DriftWatch | `http://127.0.0.1:5008` |

Override any of these per-run with `--huntforge-url`, `--atomicloop-url`, `--driftwatch-url`.

### Authentication

If your AtomicLoop instance has auth enabled, set:

```bash
export ATOMICLOOP_API_KEY="your-key-here"
```

purple-loop sends this as an `X-API-Key` header on both `/api/run` and `/api/validate` calls. If it's unset, purple-loop logs a warning at startup and sends requests without the header.

---

## Usage

### Dry run (preview only, no execution)

```bash
python main.py --technique T1059.001 --dry-run
```

### Live execution

```bash
python main.py --technique T1059.001 --confirm
```

### Specify a test number

```bash
python main.py --technique T1059.001 --test 2 --confirm
```

### Pass input arguments to the atomic test

```bash
python main.py --technique T1059.001 --confirm --arg target_url=http://127.0.0.1:8080
```

### Skip HuntForge and supply your own Sigma rule

```bash
python main.py --technique T1059.001 --confirm --sigma /path/to/rule.yml
```

### All flags

| Flag | Default | Meaning |
|---|---|---|
| `--technique` | *(required)* | ATT&CK technique ID, e.g. `T1059.001` |
| `--test` | `1` | Test number within the technique |
| `--confirm` | off | Required to execute live |
| `--dry-run` | off | Preview only, never executes |
| `--sigma` | none | Path to a Sigma rule YAML — skips HuntForge |
| `--arg KEY=VALUE` | none | Input argument for the atomic test (repeatable) |
| `--output` | `./output` | Report output directory |
| `--huntforge-url` | `http://127.0.0.1:5007` | HuntForge base URL |
| `--atomicloop-url` | `http://127.0.0.1:5011` | AtomicLoop base URL |
| `--driftwatch-url` | `http://127.0.0.1:5008` | DriftWatch base URL |
| `--timeout` | `60` | HTTP request timeout (seconds) |
| `--exec-timeout` | `30` | Atomic test execution timeout (seconds) |
| `--log-level` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |

---

## Output

Each run writes one JSON report to `output_dir` (default `./output`):

```
purple_loop_{technique}_test{N}_{timestamp}.json
```

containing `loop_id`, `timestamp`, `technique_id`, `test_number`, `dry_run`, `detection_fired`, `huntforge_playbook`, `sigma_rule`, `atomic_run`, and `validation`.

A summary is also printed to stdout: mode (dry-run/live), exit code, event count, duration, detection fired/missed with match count, and gap analysis (if DriftWatch returned one).

---

## Validation status

Validated end-to-end in April 2026 against **T1059.001**, exercising the full loop: HuntForge playbook generation → AtomicLoop execution and event capture → DriftWatch rule validation → report generation.

---

## License

This project is licensed under the MIT License — see the root [LICENSE](../../LICENSE) file for details.
