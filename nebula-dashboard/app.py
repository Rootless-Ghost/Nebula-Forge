#!/usr/bin/env python3
"""
nebula-dashboard — Nebula Forge central hub.

Serves a dark-theme dashboard showing:
  - Online/offline status of every Nebula Forge tool
  - Launch links to each tool's UI
  - Recent run summaries for ir-chain and detection-pipeline

Usage:
    python app.py
    python app.py --config /path/to/config.yaml
    python app.py --port 5010
"""

import argparse
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import yaml
from flask import Flask, jsonify, render_template

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("nebula-dashboard")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "tools": {
        "sigmaforge": {
            "label":       "SigmaForge",
            "url":         "http://127.0.0.1:5000",
            "health_path": "/api/log-sources",
            "description": "Sigma rule generator",
            "category":    "Detection",
        },
        "threat_intel": {
            "label":       "Threat Intel Dashboard",
            "url":         "http://127.0.0.1:5001",
            "health_path": "/api/health",
            "description": "IOC intelligence & enrichment",
            "category":    "Intelligence",
        },
        "yaraforge": {
            "label":       "YaraForge",
            "url":         "http://127.0.0.1:5002",
            "health_path": "/",
            "description": "YARA rule editor & tester",
            "category":    "Detection",
        },
        "snortforge": {
            "label":       "SnortForge",
            "url":         "http://127.0.0.1:5003",
            "health_path": "/api/templates",
            "description": "Snort 2 / Snort 3 rule builder",
            "category":    "Detection",
        },
        "siren": {
            "label":       "SIREN",
            "url":         "http://127.0.0.1:5004",
            "health_path": "/api/sample",
            "description": "Incident report generator",
            "category":    "Response",
        },
        "endpointforge": {
            "label":       "EndpointForge",
            "url":         "http://127.0.0.1:5005",
            "health_path": "/",
            "description": "Endpoint detection rule builder",
            "category":    "Detection",
        },
        "lognorm": {
            "label":       "LogNorm",
            "url":         "http://127.0.0.1:5006",
            "health_path": "/api/health",
            "description": "Log source normalizer — Sysmon / WEL / Wazuh / syslog / CEF → ECS-lite",
            "category":    "Normalize",
        },
        "huntforge": {
            "label":       "HuntForge",
            "url":         "http://127.0.0.1:5007",
            "health_path": "/api/health",
            "description": "MITRE ATT&CK threat hunt playbook generator",
            "category":    "Detection",
        },
        "driftwatch": {
            "label":       "DriftWatch",
            "url":         "http://127.0.0.1:5008",
            "health_path": "/api/health",
            "description": "Detection drift analyzer for Sigma rules",
            "category":    "Detection",
        },
        "clusteriq": {
            "label":       "ClusterIQ",
            "url":         "http://127.0.0.1:5009",
            "health_path": "/api/health",
            "description": "Contextual alert clustering engine",
            "category":    "Detection",
        },
    },
    "pipelines": {
        "ir_chain": {
            "label":              "ir-chain",
            "description":        "EndpointTriage → log-analyzer → SIREN",
            "triage_output_path": "../EndpointTriage/TriageOutput",
            "siren_reports_dir":  "../ir-chain/siren_reports",
            "processed_marker":   ".irchain_processed",
            "max_recent":         5,
        },
        "detection_pipeline": {
            "label":       "detection-pipeline",
            "description": "IOC → Threat Intel → Sigma / YARA / Snort",
            "output_dir":  "../detection-pipeline/output",
            "max_recent":  5,
        },
    },
    "health_timeout": 3,
    "port": 5010,
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into a copy of base."""
    result = dict(base)
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and key in result
            and isinstance(result[key], dict)
        ):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str) -> dict:
    config = _deep_merge({}, _DEFAULTS)
    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config = _deep_merge(config, loaded)
        logger.debug("Config loaded from %s", path)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

app = Flask(__name__)
_config: dict = {}


def create_app(config_path: str = "config.yaml") -> Flask:
    global _config
    _config = load_config(config_path)
    return app


# ---------------------------------------------------------------------------
# Health checking
# ---------------------------------------------------------------------------

def _check_tool(key: str, tool: dict, timeout: int) -> dict:
    url = tool["url"].rstrip("/") + tool["health_path"]
    try:
        resp = requests.get(url, timeout=timeout)
        online = resp.status_code < 500
        return {
            "key":         key,
            "label":       tool["label"],
            "url":         tool["url"],
            "description": tool["description"],
            "category":    tool["category"],
            "online":      online,
            "status_code": resp.status_code,
            "error":       None,
        }
    except requests.exceptions.ConnectionError:
        return {
            "key":         key,
            "label":       tool["label"],
            "url":         tool["url"],
            "description": tool["description"],
            "category":    tool["category"],
            "online":      False,
            "status_code": None,
            "error":       "Connection refused",
        }
    except requests.exceptions.Timeout:
        return {
            "key":         key,
            "label":       tool["label"],
            "url":         tool["url"],
            "description": tool["description"],
            "category":    tool["category"],
            "online":      False,
            "status_code": None,
            "error":       "Timeout",
        }
    except Exception as exc:
        return {
            "key":         key,
            "label":       tool["label"],
            "url":         tool["url"],
            "description": tool["description"],
            "category":    tool["category"],
            "online":      False,
            "status_code": None,
            "error":       str(exc),
        }


@app.route("/api/status")
def api_status():
    tools_cfg = _config.get("tools", {})
    timeout = int(_config.get("health_timeout", 3))
    results = []
    with ThreadPoolExecutor(max_workers=len(tools_cfg) or 1) as pool:
        futures = {
            pool.submit(_check_tool, key, tool, timeout): key
            for key, tool in tools_cfg.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    # Stable order: sort by label
    results.sort(key=lambda r: r["label"])
    online_count = sum(1 for r in results if r["online"])
    return jsonify({
        "tools":        results,
        "online_count": online_count,
        "total_count":  len(results),
        "checked_at":   datetime.utcnow().isoformat() + "Z",
    })


# ---------------------------------------------------------------------------
# Pipeline status helpers
# ---------------------------------------------------------------------------

def _irchain_status() -> dict:
    cfg = _config.get("pipelines", {}).get("ir_chain", {})
    triage_path = os.path.abspath(cfg.get("triage_output_path", ""))
    reports_dir = os.path.abspath(cfg.get("siren_reports_dir", ""))
    marker = cfg.get("processed_marker", ".irchain_processed")
    max_recent = int(cfg.get("max_recent", 5))

    # Count case folders and processed ones
    total_cases = 0
    processed_cases = 0
    case_pattern = re.compile(r"^[A-Za-z0-9_-]+_\d{8}_\d{6}$")

    if os.path.isdir(triage_path):
        for entry in os.scandir(triage_path):
            if entry.is_dir() and case_pattern.match(entry.name):
                total_cases += 1
                if os.path.exists(os.path.join(entry.path, marker)):
                    processed_cases += 1

    # Recent SIREN report files
    recent_reports = []
    if os.path.isdir(reports_dir):
        json_files = []
        for fname in os.listdir(reports_dir):
            if fname.endswith(".json") and not fname.startswith("fallback_"):
                fpath = os.path.join(reports_dir, fname)
                try:
                    mtime = os.path.getmtime(fpath)
                    json_files.append((mtime, fname, fpath))
                except OSError:
                    pass
        json_files.sort(reverse=True)
        for mtime, fname, fpath in json_files[:max_recent]:
            try:
                with open(fpath, encoding="utf-8") as fh:
                    data = json.load(fh)
                recent_reports.append({
                    "file":     fname,
                    "hostname": data.get("affected_systems", [{}])[0] if data.get("affected_systems") else "",
                    "title":    data.get("title", fname),
                    "severity": data.get("severity", ""),
                    "date":     data.get("detection_date", ""),
                    "modified": datetime.utcfromtimestamp(mtime).isoformat() + "Z",
                })
            except Exception:
                recent_reports.append({
                    "file":     fname,
                    "title":    fname,
                    "modified": datetime.utcfromtimestamp(mtime).isoformat() + "Z",
                })

    return {
        "label":            cfg.get("label", "ir-chain"),
        "description":      cfg.get("description", ""),
        "total_cases":      total_cases,
        "processed_cases":  processed_cases,
        "pending_cases":    total_cases - processed_cases,
        "recent_reports":   recent_reports,
        "triage_path_ok":   os.path.isdir(triage_path),
        "reports_path_ok":  os.path.isdir(reports_dir),
    }


def _detection_pipeline_status() -> dict:
    cfg = _config.get("pipelines", {}).get("detection_pipeline", {})
    output_dir = os.path.abspath(cfg.get("output_dir", ""))
    max_recent = int(cfg.get("max_recent", 5))

    recent_runs = []
    if os.path.isdir(output_dir):
        run_dirs = []
        for entry in os.scandir(output_dir):
            if entry.is_dir():
                summary_path = os.path.join(entry.path, "summary.json")
                if os.path.exists(summary_path):
                    try:
                        mtime = os.path.getmtime(summary_path)
                        run_dirs.append((mtime, entry.name, summary_path))
                    except OSError:
                        pass
        run_dirs.sort(reverse=True)

        for mtime, run_name, summary_path in run_dirs[:max_recent]:
            try:
                with open(summary_path, encoding="utf-8") as fh:
                    summary = json.load(fh)
                totals = summary.get("totals", {})
                generated = summary.get("rules_generated", {})
                failed = summary.get("rules_failed", {})
                recent_runs.append({
                    "run":          run_name,
                    "timestamp":    summary.get("timestamp", ""),
                    "input_iocs":   totals.get("input_iocs", 0),
                    "processed":    totals.get("processed", 0),
                    "filtered_out": totals.get("filtered_out", 0),
                    "rules_generated": generated,
                    "rules_failed":    failed,
                    "modified":        datetime.utcfromtimestamp(mtime).isoformat() + "Z",
                })
            except Exception:
                recent_runs.append({
                    "run":      run_name,
                    "modified": datetime.utcfromtimestamp(mtime).isoformat() + "Z",
                })

    return {
        "label":          cfg.get("label", "detection-pipeline"),
        "description":    cfg.get("description", ""),
        "recent_runs":    recent_runs,
        "output_path_ok": os.path.isdir(output_dir),
    }


@app.route("/api/reports")
def api_reports():
    """Return all SIREN incident reports from siren_reports_dir, newest first."""
    cfg = _config.get("pipelines", {}).get("ir_chain", {})
    reports_dir = os.path.abspath(cfg.get("siren_reports_dir", ""))

    reports = []
    if os.path.isdir(reports_dir):
        for fname in os.listdir(reports_dir):
            if not fname.endswith(".json") or fname.startswith("fallback_"):
                continue
            fpath = os.path.join(reports_dir, fname)
            try:
                mtime = os.path.getmtime(fpath)
                with open(fpath, encoding="utf-8") as fh:
                    data = json.load(fh)
                data["_file"] = fname
                data["_modified"] = datetime.utcfromtimestamp(mtime).isoformat() + "Z"
                reports.append((mtime, data))
            except Exception as exc:
                logger.warning("Could not read report %s: %s", fname, exc)

    reports.sort(key=lambda x: x[0], reverse=True)
    return jsonify([r for _, r in reports])


@app.route("/api/pipeline/ir-chain")
def api_pipeline_irchain():
    return jsonify(_irchain_status())


@app.route("/api/pipeline/detection-pipeline")
def api_pipeline_detection():
    return jsonify(_detection_pipeline_status())


# ---------------------------------------------------------------------------
# Main page
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="nebula-dashboard")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--debug", action="store_true")
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    create_app(args.config)

    port = args.port if args.port is not None else int(_config.get("port", 5010))
    logger.info("nebula-dashboard starting on http://127.0.0.1:%d", port)
    app.run(debug=args.debug, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
