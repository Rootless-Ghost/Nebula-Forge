#!/usr/bin/env python3
"""
drift-scan — Log normalization + Sigma drift analysis pipeline.

Reads raw log events from a file or directory, normalizes them via LogNorm,
fetches Sigma rules from SigmaForge, then runs DriftWatch drift analysis to
surface coverage gaps and stale/missing detections.

Usage
-----
Scan a log file:
    python main.py --input /path/to/events.json --source sysmon

Scan a directory (all .json/.log files):
    python main.py --input /path/to/logs/ --source wel

Set look-back window (hours) and save report:
    python main.py --input /path/to/events.json --source sysmon --window 168

Custom config:
    python main.py --input /path/to/events.json --config /path/to/config.yaml

Dry run (normalize only, skip DriftWatch):
    python main.py --input /path/to/events.json --dry-run
"""

import argparse
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("drift-scan")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "lognorm_url":    "http://127.0.0.1:5006",
    "sigmaforge_url": "http://127.0.0.1:5000",
    "driftwatch_url": "http://127.0.0.1:5008",
    "output_dir":     os.path.join(os.path.dirname(__file__), "output"),
    "window_hours":   168,
    "timeout":        30,
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post(url: str, payload: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _get(url: str, timeout: int) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Step 1 — Load raw events from file(s)
# ---------------------------------------------------------------------------

def load_events(input_path: str) -> list:
    """Return a flat list of raw event dicts from a file or directory."""
    events = []

    if os.path.isfile(input_path):
        paths = [input_path]
    elif os.path.isdir(input_path):
        paths = []
        for fname in sorted(os.listdir(input_path)):
            if fname.endswith((".json", ".log")):
                paths.append(os.path.join(input_path, fname))
        if not paths:
            logger.warning("No .json/.log files found in %s", input_path)
    else:
        logger.error("Input path does not exist: %s", input_path)
        sys.exit(1)

    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                content = json.load(fh)
            if isinstance(content, list):
                events.extend(content)
            elif isinstance(content, dict):
                # Support {"events": [...]} or {"logs": [...]} wrappers
                if "events" in content:
                    events.extend(content["events"])
                elif "logs" in content:
                    events.extend(content["logs"])
                else:
                    events.append(content)
            logger.info("Loaded %d events from %s", len(events), path)
        except Exception as exc:
            logger.warning("Could not load %s: %s", path, exc)

    logger.info("Total events loaded: %d", len(events))
    return events


# ---------------------------------------------------------------------------
# Step 2 — Normalize via LogNorm
# ---------------------------------------------------------------------------

def normalize_events(events: list, source: str, lognorm_url: str, timeout: int) -> list:
    """POST events to LogNorm /api/normalize/batch; return ECS-lite events."""
    url = lognorm_url.rstrip("/") + "/api/normalize/batch"
    logger.info("Normalizing %d events via LogNorm (%s)…", len(events), url)
    try:
        result = _post(url, {"events": events, "source": source}, timeout)
        normalized = result.get("normalized", result if isinstance(result, list) else [])
        logger.info("LogNorm returned %d normalized events", len(normalized))
        return normalized
    except urllib.error.URLError as exc:
        logger.warning("LogNorm unavailable (%s) — using raw events", exc)
        return events
    except Exception as exc:
        logger.warning("LogNorm error: %s — using raw events", exc)
        return events


# ---------------------------------------------------------------------------
# Step 3 — Fetch Sigma rules from SigmaForge
# ---------------------------------------------------------------------------

def fetch_sigma_rules(sigmaforge_url: str, timeout: int) -> list:
    """GET /api/rules from SigmaForge; return list of rule YAML strings."""
    url = sigmaforge_url.rstrip("/") + "/api/rules"
    logger.info("Fetching Sigma rules from SigmaForge (%s)…", url)
    try:
        result = _get(url, timeout)
        rules = result if isinstance(result, list) else result.get("rules", [])
        # Each rule may be a dict with a 'content' or 'yaml' field, or a raw string
        extracted = []
        for r in rules:
            if isinstance(r, str):
                extracted.append(r)
            elif isinstance(r, dict):
                extracted.append(r.get("content") or r.get("yaml") or json.dumps(r))
        logger.info("Fetched %d Sigma rules from SigmaForge", len(extracted))
        return extracted
    except urllib.error.URLError as exc:
        logger.warning("SigmaForge unavailable (%s) — proceeding without rules", exc)
        return []
    except Exception as exc:
        logger.warning("SigmaForge error: %s — proceeding without rules", exc)
        return []


# ---------------------------------------------------------------------------
# Step 4 — Run DriftWatch analysis
# ---------------------------------------------------------------------------

def run_driftwatch(
    events: list,
    rules: list,
    window_hours: int,
    driftwatch_url: str,
    timeout: int,
) -> dict | None:
    """POST events + rules to DriftWatch /api/analyze; return analysis report."""
    if not rules:
        logger.warning("No Sigma rules available — skipping DriftWatch analysis")
        return None

    url = driftwatch_url.rstrip("/") + "/api/analyze"
    logger.info(
        "Running DriftWatch analysis: %d events × %d rules (%s)…",
        len(events), len(rules), url,
    )
    payload = {
        "events":            events,
        "rules":             rules,
        "time_window_hours": window_hours,
    }
    try:
        result = _post(url, payload, timeout)
        logger.info("DriftWatch analysis complete")
        return result
    except urllib.error.URLError as exc:
        logger.warning("DriftWatch unavailable (%s) — skipping drift analysis", exc)
        return None
    except Exception as exc:
        logger.warning("DriftWatch error: %s — skipping drift analysis", exc)
        return None


# ---------------------------------------------------------------------------
# Step 5 — Save report
# ---------------------------------------------------------------------------

def save_report(
    output_dir: str,
    events: list,
    normalized: list,
    rules: list,
    drift_result: dict | None,
    source: str,
    window_hours: int,
    input_path: str,
) -> str:
    """Write timestamped JSON report to output_dir; return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"drift_scan_{ts}.json"
    fpath = os.path.join(output_dir, fname)

    report = {
        "scan_id":          f"drift-scan-{ts}",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "input_path":       input_path,
        "source":           source,
        "window_hours":     window_hours,
        "raw_event_count":  len(events),
        "norm_event_count": len(normalized),
        "rule_count":       len(rules),
        "drift_analysis":   drift_result,
    }

    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    logger.info("Report saved: %s", fpath)
    return fpath


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(report_path: str, events: list, normalized: list, rules: list, drift_result: dict | None) -> None:
    width = 60
    print("\n" + "=" * width)
    print("  DRIFT-SCAN SUMMARY")
    print("=" * width)
    print(f"  Raw events loaded   : {len(events)}")
    print(f"  Normalized events   : {len(normalized)}")
    print(f"  Sigma rules fetched : {len(rules)}")

    if drift_result:
        gaps        = drift_result.get("gaps",        drift_result.get("gap_count",   "N/A"))
        covered     = drift_result.get("covered",     drift_result.get("fired_count",  "N/A"))
        total_rules = drift_result.get("total_rules", len(rules))
        print(f"  Rules with gaps     : {gaps}")
        print(f"  Rules with coverage : {covered} / {total_rules}")
    else:
        print("  Drift analysis      : skipped (DriftWatch unavailable or no rules)")

    print(f"\n  Report              : {report_path}")
    print("=" * width + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="drift-scan — normalize logs + analyze Sigma rule drift"
    )
    p.add_argument("--input",   required=True, help="Log file or directory path")
    p.add_argument(
        "--source",
        default="sysmon",
        choices=["sysmon", "wel", "wazuh", "syslog", "cef"],
        help="Log source type for LogNorm (default: sysmon)",
    )
    p.add_argument(
        "--window",
        type=int,
        default=None,
        help="Look-back window in hours for DriftWatch (default: 168)",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Output directory for reports (default: ./output)",
    )
    p.add_argument(
        "--lognorm-url",
        default=None,
        help="LogNorm base URL (default: http://127.0.0.1:5006)",
    )
    p.add_argument(
        "--sigmaforge-url",
        default=None,
        help="SigmaForge base URL (default: http://127.0.0.1:5000)",
    )
    p.add_argument(
        "--driftwatch-url",
        default=None,
        help="DriftWatch base URL (default: http://127.0.0.1:5008)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="HTTP timeout in seconds (default: 30)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Normalize only — skip DriftWatch analysis",
    )
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    cfg = dict(_DEFAULTS)
    if args.lognorm_url:
        cfg["lognorm_url"] = args.lognorm_url
    if args.sigmaforge_url:
        cfg["sigmaforge_url"] = args.sigmaforge_url
    if args.driftwatch_url:
        cfg["driftwatch_url"] = args.driftwatch_url
    if args.output:
        cfg["output_dir"] = args.output
    if args.window:
        cfg["window_hours"] = args.window
    if args.timeout:
        cfg["timeout"] = args.timeout

    timeout      = int(cfg["timeout"])
    window_hours = int(cfg["window_hours"])
    output_dir   = cfg["output_dir"]

    # Step 1: load
    events = load_events(args.input)
    if not events:
        logger.error("No events to process — exiting")
        sys.exit(1)

    # Step 2: normalize
    normalized = normalize_events(events, args.source, cfg["lognorm_url"], timeout)

    # Step 3: fetch Sigma rules
    rules = fetch_sigma_rules(cfg["sigmaforge_url"], timeout)

    # Step 4: drift analysis
    drift_result = None
    if not args.dry_run:
        drift_result = run_driftwatch(normalized, rules, window_hours, cfg["driftwatch_url"], timeout)
    else:
        logger.info("Dry run — skipping DriftWatch analysis")

    # Step 5: save report
    report_path = save_report(
        output_dir, events, normalized, rules, drift_result,
        args.source, window_hours, args.input,
    )

    print_summary(report_path, events, normalized, rules, drift_result)


if __name__ == "__main__":
    main()
