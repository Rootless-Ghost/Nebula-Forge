#!/usr/bin/env python3
"""
ir-chain — main entry point.

Usage
-----
Watch mode (default):
    python main.py
    python main.py --config path/to/config.yaml

Process existing unprocessed cases then exit:
    python main.py --once

Re-process a specific case folder (ignores processed marker):
    python main.py --case /path/to/TriageOutput/WORKSTATION01_20260412_141500
"""

import argparse
import logging
import os
import queue
import signal
import sys

import yaml

from irchain import watcher as watcher_mod
from irchain.log_runner import analyze_triage_logs
from irchain.siren_client import post_to_siren
from irchain.transformer import build_siren_payload

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ir-chain")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    "triage_output_path": "./TriageOutput",
    "log_analyzer_script": "../log-analyzer/src/log_analyzer.py",
    "log_analyzer_python": sys.executable,
    "siren_url": "http://127.0.0.1:5000",
    "analyst": "ir-chain (automated)",
    "poll_interval_seconds": 5,
    "processed_marker": ".irchain_processed",
    "temp_dir": "./tmp",
    "output_dir": "./siren_reports",
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    if not os.path.exists(path):
        logger.warning("Config file not found: %s — using defaults", path)
        return config
    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        config.update(loaded)
        logger.info("Loaded config from %s", path)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)
    return config


# ---------------------------------------------------------------------------
# Case processing
# ---------------------------------------------------------------------------

def process_case(case_path: str, config: dict) -> bool:
    """
    Run the full ir-chain pipeline for one EndpointTriage case folder.

    Returns True on success (SIREN accepted the report or fallback saved),
    False if a critical error prevented processing.
    """
    case_name = os.path.basename(case_path.rstrip("/\\"))
    logger.info("=" * 60)
    logger.info("Processing case: %s", case_name)
    logger.info("=" * 60)

    # 1. Run log-analyzer against the case's Security.csv
    alerts = analyze_triage_logs(case_path, config)

    # 2. Transform triage data + alerts into SIREN payload
    try:
        payload = build_siren_payload(case_path, alerts, config)
    except Exception as exc:
        logger.error("Transformer failed for %s: %s", case_name, exc, exc_info=True)
        return False

    logger.info(
        "Payload built: title=%r  severity=%s  category=%s  "
        "timeline_events=%d  iocs=%d  recommendations=%d",
        payload.get("title"),
        payload.get("severity"),
        payload.get("category"),
        len(payload.get("timeline_events", [])),
        len(payload.get("iocs", [])),
        len(payload.get("recommendations", [])),
    )

    # 3. POST to SIREN
    output_dir = os.path.abspath(config.get("output_dir", "./siren_reports"))
    result = post_to_siren(payload, config["siren_url"], output_dir, case_name)

    # 4. Write processed marker
    marker_path = os.path.join(case_path, config["processed_marker"])
    try:
        with open(marker_path, "w", encoding="utf-8") as fh:
            fh.write(
                f"Processed by ir-chain\n"
                f"SIREN incident_id: {result.get('incident_id', 'N/A') if result else 'fallback'}\n"
            )
    except OSError as exc:
        logger.warning("Could not write processed marker: %s", exc)

    if result:
        logger.info(
            "Case complete: incident_id=%s", result.get("incident_id", "?")
        )
    else:
        logger.warning(
            "SIREN was unavailable — fallback payload saved to %s", output_dir
        )

    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ir-chain: EndpointTriage → log-analyzer → SIREN pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    p.add_argument(
        "--once", action="store_true",
        help="Process any existing unprocessed cases then exit (no watcher)",
    )
    p.add_argument(
        "--case",
        help="Process a single specific case folder and exit",
    )
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log verbosity (default: INFO)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    config = load_config(args.config)

    _print_banner(config)

    # ------------------------------------------------------------------ #
    # Mode: single case                                                    #
    # ------------------------------------------------------------------ #
    if args.case:
        case_path = os.path.abspath(args.case)
        if not os.path.isdir(case_path):
            logger.error("Case path does not exist: %s", case_path)
            sys.exit(1)
        success = process_case(case_path, config)
        sys.exit(0 if success else 1)

    # ------------------------------------------------------------------ #
    # Mode: --once (drain existing cases then exit)                        #
    # ------------------------------------------------------------------ #
    triage_output = os.path.abspath(config["triage_output_path"])

    existing = watcher_mod.scan_existing(triage_output, config["processed_marker"])
    if existing:
        logger.info("Found %d unprocessed existing case(s)", len(existing))
        for cp in existing:
            process_case(cp, config)
    else:
        logger.info("No unprocessed existing cases found")

    if args.once:
        logger.info("--once flag set, exiting")
        return

    # ------------------------------------------------------------------ #
    # Mode: watch (default)                                               #
    # ------------------------------------------------------------------ #
    case_queue: queue.Queue = queue.Queue()
    observer = watcher_mod.start_watcher(triage_output, case_queue, config["processed_marker"])

    # Graceful shutdown on Ctrl-C / SIGTERM
    running = [True]

    def _shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping watcher")
        running[0] = False
        observer.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    logger.info(
        "Watching for new EndpointTriage cases in: %s  (Ctrl-C to stop)",
        triage_output,
    )

    poll = float(config.get("poll_interval_seconds", 5))

    while running[0]:
        try:
            case_path = case_queue.get(timeout=poll)
            process_case(case_path, config)
            case_queue.task_done()
        except queue.Empty:
            # Normal; no new case arrived in this interval
            pass
        except Exception as exc:
            logger.error("Unexpected error in main loop: %s", exc, exc_info=True)

    observer.join()
    logger.info("ir-chain stopped")


def _print_banner(config: dict) -> None:
    logger.info("")
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║  ir-chain — Incident Response Integration Chain  ║")
    logger.info("╚══════════════════════════════════════════════════╝")
    logger.info("  Triage path : %s", config.get("triage_output_path"))
    logger.info("  log-analyzer: %s", config.get("log_analyzer_script"))
    logger.info("  SIREN URL   : %s", config.get("siren_url"))
    logger.info("  Output dir  : %s", config.get("output_dir"))
    logger.info("")


if __name__ == "__main__":
    main()
