# nebula-dashboard

**nebula-dashboard** is a central hub for all Nebula Forge tools — a single page that shows which tools are running, provides one-click launch links, and surfaces recent activity from the ir-chain and detection-pipeline automation modules.

```
http://127.0.0.1:5010/
    │
    ├─ GET /api/status
    │      ↳ concurrent health-checks for all configured tools
    │
    ├─ GET /api/pipeline/ir-chain
    │      ↳ case counts from TriageOutput + recent SIREN reports
    │
    └─ GET /api/pipeline/detection-pipeline
           ↳ recent summary.json files from detection-pipeline output
```

---

## Features

| Feature | Detail |
|---|---|
| **Tool status grid** | Online / Offline badge per tool; auto-refreshes every 30 s |
| **One-click launch** | Launch button opens each tool in a new tab (disabled when offline) |
| **ir-chain panel** | Total / Processed / Pending case counts + last 5 SIREN report titles and severity |
| **detection-pipeline panel** | Last 5 run directories — IOC count, total rules generated, failures |
| **Dark theme** | Identical design tokens to the rest of Nebula Forge (SIREN / SigmaForge CSS variables) |

---

## Architecture

```
nebula-dashboard/
├── app.py              # Flask app — API routes + template render
├── config.yaml         # Tool URLs, ports, pipeline paths
├── requirements.txt
├── README.md
└── templates/
│   └── index.html      # Single-page dashboard shell
└── static/
    ├── css/
    │   └── style.css   # Dark theme (Nebula Forge design tokens)
    └── js/
        └── dashboard.js  # Status polling, panel rendering, auto-refresh
```

### API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Serve the dashboard HTML |
| `/api/status` | GET | Concurrent health-check of every configured tool |
| `/api/pipeline/ir-chain` | GET | ir-chain case counts and recent SIREN reports |
| `/api/pipeline/detection-pipeline` | GET | Recent detection-pipeline run summaries |

---

## Setup

### Prerequisites

At least one other Nebula Forge tool should be running (otherwise all cards show Offline — which is also valid).

### Install

```bash
cd nebula-dashboard
pip install -r requirements.txt
```

### Configure

Edit `config.yaml`. The defaults assume the detection-pipeline port layout:

| Tool | Default port |
|---|---|
| SigmaForge | 5000 |
| Threat Intel Dashboard | 5001 |
| YaraForge | 5002 |
| SnortForge | 5003 |
| SIREN | 5004 |
| EndpointForge | 5005 |
| **nebula-dashboard** | **5010** |

Adjust `pipelines.ir_chain.triage_output_path` and `pipelines.ir_chain.siren_reports_dir` to point at your actual paths.

---

## Usage

```bash
python app.py
```

Open `http://127.0.0.1:5010` in a browser.

### Options

```
--config PATH     Path to config.yaml (default: ./config.yaml)
--port PORT       Override the dashboard listen port (default: 5010)
--debug           Enable Flask debug mode
--log-level LEVEL DEBUG | INFO | WARNING | ERROR (default: INFO)
```

---

## Tool health probes

Each tool is probed with a lightweight GET request. The endpoint used per tool:

| Tool | Health endpoint |
|---|---|
| SigmaForge | `GET /api/log-sources` |
| Threat Intel Dashboard | `GET /api/health` |
| YaraForge | `GET /` |
| SnortForge | `GET /api/templates` |
| SIREN | `GET /api/sample` |
| EndpointForge | `GET /` |

A tool is considered **Online** if the HTTP status code is below 500. The timeout defaults to 3 s and is configurable via `health_timeout` in `config.yaml`.

---

## Pipeline panel data sources

**ir-chain**
- Scans `triage_output_path` for `{HOSTNAME}_{YYYYMMDD_HHMMSS}` directories
- A case is **Processed** if it contains the `.irchain_processed` marker
- Recent SIREN reports are read from `siren_reports_dir/*.json`

**detection-pipeline**
- Scans `output_dir` for timestamped run directories containing `summary.json`
- Displays the last N runs (configurable via `max_recent`)

---

## License

MIT
