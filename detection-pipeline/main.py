#!/usr/bin/env python3
"""
detection-pipeline — main entry point.

Usage
-----
Single IOC (inline):
    python main.py --ioc 1.2.3.4

Multiple IOCs inline:
    python main.py --ioc 1.2.3.4 --ioc evil.com --ioc e3b0c44298fc1c149...

From file:
    python main.py --file iocs.txt

Mixed:
    python main.py --ioc 1.2.3.4 --file more_iocs.txt

Override risk threshold at runtime:
    python main.py --ioc 1.2.3.4 --threshold 50

Custom config:
    python main.py --file iocs.txt --config /path/to/config.yaml

Override output directory:
    python main.py --ioc 1.2.3.4 --output ./my_rules
"""

import argparse
import json
import logging
import os
import sys

import yaml

from pipeline.dispatcher import run_pipeline
from pipeline.enricher import enrich_all
from pipeline.ioc_parser import collect_iocs
from pipeline.output_manager import save

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("detection-pipeline")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "threat_intel_url": "http://127.0.0.1:5001",
    "sigmaforge_url":   "http://127.0.0.1:5000",
    "yaraforge_url":    "http://127.0.0.1:5002",
    "snortforge_url":   "http://127.0.0.1:5003",
    "risk_threshold":   30,
    "output_dir":       "./output",
    "author":           "detection-pipeline",
    "sigma": {
        "level":        "high",
        "status":       "experimental",
        "rule_id_base": 100001,
        "group_name":   "sigma_rules",
    },
    "snort": {
        "sid_base": 1000001,
        "action":   "alert",
    },
}


def load_config(path: str) -> dict:
    config = dict(_DEFAULTS)
    config["sigma"] = dict(_DEFAULTS["sigma"])
    config["snort"] = dict(_DEFAULTS["snort"])

    if not os.path.exists(path):
        logger.warning("Config not found: %s — using defaults", path)
        return config

    try:
        with open(path, encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        # Merge top-level keys, then sub-dicts
        for key, value in loaded.items():
            if isinstance(value, dict) and key in config and isinstance(config[key], dict):
                config[key].update(value)
            else:
                config[key] = value
        logger.debug("Config loaded from %s", path)
    except Exception as exc:
        logger.error("Failed to load config: %s — using defaults", exc)

    return config


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="detection-pipeline: IOC → TID enrichment → SigmaForge + YaraForge + SnortForge",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--ioc", dest="iocs", metavar="VALUE", action="append",
        help="Inline IOC value (repeatable: --ioc 1.2.3.4 --ioc evil.com)",
    )
    p.add_argument(
        "--file", dest="ioc_file", metavar="PATH",
        help="Path to a file containing one IOC per line (# = comment)",
    )
    p.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml (default: ./config.yaml)",
    )
    p.add_argument(
        "--threshold", type=int, default=None, metavar="0-100",
        help="Override risk_threshold from config (0–100)",
    )
    p.add_argument(
        "--output", default=None, metavar="DIR",
        help="Override output_dir from config",
    )
    p.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return p.parse_args()


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(pipeline_results, run_dir: str) -> None:
    summary_path = os.path.join(run_dir, "summary.json")
    if not os.path.exists(summary_path):
        return

    with open(summary_path, encoding="utf-8") as fh:
        summary = json.load(fh)

    totals = summary.get("totals", {})
    generated = summary.get("rules_generated", {})
    failed = summary.get("rules_failed", {})

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║            detection-pipeline — Run Complete             ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Output directory : {run_dir}")
    print()
    print(f"  IOCs input       : {totals.get('input_iocs', 0)}")
    print(f"  Processed        : {totals.get('processed', 0)}")
    print(f"  Filtered out     : {totals.get('filtered_out', 0)}")
    print()
    print("  Rules generated:")
    for tool in ("sigma", "yara", "snort2", "snort3"):
        ok = generated.get(tool, 0)
        fail = failed.get(tool, 0)
        status = f"{ok} OK" + (f", {fail} failed" if fail else "")
        print(f"    {tool:<10} {status}")
    print()

    # Per-IOC table
    iocs = summary.get("iocs", [])
    if iocs:
        print(f"  {'IOC':<50} {'Type':<8} {'Score':>5}  {'Level':<8}  Rules")
        print(f"  {'-'*50} {'-'*8} {'-'*5}  {'-'*8}  -----")
        for entry in iocs:
            tools_ok = [t for t, r in entry.get("rules", {}).items()
                        if isinstance(r, dict) and r.get("success")]
            tools_ok = [t for t in tools_ok if t != "sigma_conversions"]
            value = entry["value"]
            if len(value) > 48:
                value = value[:45] + "..."
            print(
                f"  {value:<50} {entry['ioc_type']:<8} {entry['risk_score']:>5}"
                f"  {entry['risk_level']:<8}  {', '.join(sorted(tools_ok))}"
            )

    filtered_path = os.path.join(run_dir, "filtered_out.json")
    if os.path.exists(filtered_path):
        with open(filtered_path, encoding="utf-8") as fh:
            filtered = json.load(fh)
        if filtered:
            print()
            print(f"  Filtered out ({len(filtered)}):")
            for entry in filtered:
                print(f"    {entry['value']:<50} {entry.get('reason', '')}")

    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    config = load_config(args.config)

    # CLI overrides
    if args.threshold is not None:
        config["risk_threshold"] = args.threshold
    if args.output is not None:
        config["output_dir"] = args.output

    _print_banner(config)

    # 1. Collect IOCs
    if not args.iocs and not args.ioc_file:
        logger.error("No IOCs provided. Use --ioc VALUE or --file PATH.")
        sys.exit(1)

    try:
        ioc_values = collect_iocs(args.iocs, args.ioc_file)
    except FileNotFoundError as exc:
        logger.error(str(exc))
        sys.exit(1)

    if not ioc_values:
        logger.error("No valid IOCs found after parsing.")
        sys.exit(1)

    # 2. Enrich via Threat Intel Dashboard
    enriched_iocs = enrich_all(ioc_values, config["threat_intel_url"])

    # 3. Filter + dispatch to all rule builders
    risk_threshold = int(config.get("risk_threshold", 30))
    logger.info("Risk threshold: %d — IOCs below this score will be skipped", risk_threshold)

    pipeline_results = run_pipeline(enriched_iocs, config, risk_threshold)

    # 4. Save output
    output_dir = os.path.abspath(config.get("output_dir", "./output"))
    run_dir = save(pipeline_results, output_dir)

    # 5. Print summary table
    _print_summary(pipeline_results, run_dir)


def _print_banner(config: dict) -> None:
    logger.info("")
    logger.info("╔══════════════════════════════════════════════════════════╗")
    logger.info("║  detection-pipeline — IOC → TID → Sigma/YARA/Snort       ║")
    logger.info("╚══════════════════════════════════════════════════════════╝")
    logger.info("  Threat Intel Dashboard : %s", config.get("threat_intel_url"))
    logger.info("  SigmaForge             : %s", config.get("sigmaforge_url"))
    logger.info("  YaraForge              : %s", config.get("yaraforge_url"))
    logger.info("  SnortForge             : %s", config.get("snortforge_url"))
    logger.info("  Risk threshold         : %s", config.get("risk_threshold"))
    logger.info("  Output directory       : %s", config.get("output_dir"))
    logger.info("")


if __name__ == "__main__":
    main()
