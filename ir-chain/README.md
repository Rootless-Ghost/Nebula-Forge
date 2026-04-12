# ir-chain

**ir-chain** is an integration pipeline that connects three Nebula-Forge tools into a single automated workflow:

```
EndpointTriage  →  log-analyzer  →  SIREN
(CSV artefacts)    (alert engine)   (incident report)
```

When EndpointTriage finishes collecting forensic artefacts from a Windows host, ir-chain detects the new output folder, feeds the relevant event-log CSVs to log-analyzer, transforms all collected data into a structured incident payload, and POSTs it to SIREN's `/api/generate` endpoint — producing a complete, analyst-ready incident report with zero manual transcription.

---

## Architecture

```
ir-chain/
├── main.py                  # Entry point — watcher loop and CLI
├── config.yaml              # Runtime configuration
├── requirements.txt
├── README.md
└── irchain/
    ├── __init__.py
    ├── models.py            # LogAlert and TriageCase dataclasses
    ├── watcher.py           # watchdog-based filesystem monitor
    ├── log_runner.py        # CSV adapter + log-analyzer subprocess runner
    ├── transformer.py       # Triage data → SIREN JSON schema
    └── siren_client.py      # HTTP POST to SIREN /api/generate
```

### Pipeline stages

| Stage | Module | What it does |
|---|---|---|
| **Watch** | `watcher.py` | Monitors the EndpointTriage output directory for new `{HOSTNAME}_{YYYYMMDD_HHMMSS}` folders. A case is considered complete when `triage_report.html` appears. |
| **Adapt + Analyse** | `log_runner.py` | Converts EndpointTriage's `Security.csv` (WinEvent format) to the column schema expected by log-analyzer, then invokes `log_analyzer.py` via subprocess and parses the terminal output into structured `LogAlert` objects. |
| **Transform** | `transformer.py` | Reads all relevant EndpointTriage CSVs, merges them with log-analyzer alerts, and builds a SIREN-compatible JSON payload including timeline events, IOCs, affected systems, severity, category, executive summary, and recommendations. |
| **Submit** | `siren_client.py` | POSTs the payload to `POST /api/generate` and saves the resulting Markdown and JSON reports to `output_dir`. Falls back to saving the payload locally if SIREN is unreachable. |

---

## Schema bridging

EndpointTriage exports Windows event logs using PowerShell's `Get-WinEvent | Select-Object`, which produces:

```
TimeCreated, Id, LevelDisplayName, ProviderName, Message, RecordId, UserId
```

log-analyzer's `parse_windows_log()` expects:

```
TimeCreated, EventID, SourceIP, TargetUserName, LogonType, Status
```

`log_runner.adapt_security_csv()` bridges this gap by:

1. Renaming `Id` → `EventID`
2. Deriving `Status` from the EventID (4624 = Success, 4625 = Failure)
3. Extracting `SourceIP`, `TargetUserName`, and `LogonType` from the rich Windows event `Message` field using targeted regex patterns

The adapted CSV is written to `temp_dir` and cleaned up after the run.

---

## Setup

### Prerequisites

- Python 3.10+
- [EndpointTriage](https://github.com/Rootless-Ghost/EndpointTriage) — run on Windows endpoints to produce the triage output folders
- [log-analyzer](https://github.com/Rootless-Ghost/log-analyzer) — the analysis engine
- [SIREN](https://github.com/Rootless-Ghost/SIREN) — running on `http://127.0.0.1:5000` (or configure a different URL)

### Install

```bash
cd ir-chain
pip install -r requirements.txt
```

### Configure

Edit `config.yaml` to point at the correct paths for your environment:

```yaml
triage_output_path: "../EndpointTriage/TriageOutput"
log_analyzer_script: "../log-analyzer/src/log_analyzer.py"
log_analyzer_python: "python"
siren_url: "http://127.0.0.1:5000"
analyst: "SOC Analyst"
output_dir: "./siren_reports"
```

---

## Usage

### Watch mode (default)

Start ir-chain and leave it running. It will process any existing unprocessed cases on startup, then watch for new ones in real time:

```bash
python main.py
```

With a custom config path:

```bash
python main.py --config /path/to/config.yaml
```

### Process existing cases and exit

Drain any unprocessed cases already present in the triage output directory, then stop:

```bash
python main.py --once
```

### Process a single specific case folder

Useful for testing or re-running a case:

```bash
python main.py --case /path/to/TriageOutput/WORKSTATION01_20260412_141500
```

Note: `--case` ignores the processed marker and always re-runs.

### Increase log verbosity

```bash
python main.py --log-level DEBUG
```

---

## Output

For each processed case ir-chain writes to `output_dir` (default `./siren_reports`):

| File | Contents |
|---|---|
| `IR-YYYYMMDD-XXXX.md` | Full incident report in Markdown (from SIREN) |
| `IR-YYYYMMDD-XXXX.json` | Full incident report as structured JSON (from SIREN) |
| `fallback_{case}_{ts}.json` | Raw payload saved locally if SIREN was unreachable |

A `.irchain_processed` marker file is also written inside each triage case folder to prevent duplicate processing across restarts.

---

## SIREN payload mapping

The transformer maps EndpointTriage artefacts to SIREN fields as follows:

| SIREN field | Source |
|---|---|
| `title` | `"Endpoint Triage: {hostname} — {triage_timestamp}"` |
| `severity` | Derived from log-analyzer alert severity counts, suspicious process flags, and high-risk persistence categories (WMI subscriptions, IFEO, AppInit_DLLs) |
| `category` | Derived from alert rule types and process/persistence flags: `Malware Incident` when OFFICE_CHILD/SUSPICIOUS_CLI/WMI/IFEO flags present; `Unauthorized Access` for brute force/privilege escalation; `Other` otherwise |
| `detection_date` | `TriageTimestamp` from `system/system_info.csv` |
| `timeline_events` | Triage completion event + one entry per log-analyzer alert + flagged processes + persistence items + suspicious scheduled tasks + suspicious recently modified files |
| `iocs` | External IPs from established TCP connections, SHA256 hashes of flagged processes, source IPs and usernames from log-analyzer alerts |
| `affected_systems` | Host info from `system/system_info.csv`, local IP inferred from `network/tcp_connections.csv` |
| `recommendations` | Base set + alert-type-specific guidance + process-flag-specific ASR/AppLocker rules + persistence-specific removal steps |
| `executive_summary` | Auto-generated paragraph summarising alert counts, flagged process count, persistence item count, and external connection count |

Fields `containment_date`, `eradication_date`, and `recovery_date` are left blank for the analyst to complete.

---

## Tested against

- EndpointTriage v1.0.0
- log-analyzer v1.0
- SIREN (flask, `POST /api/generate` schema as of `sample_qakbot_incident.json`)

---

## License

MIT
