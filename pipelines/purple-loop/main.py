#!/usr/bin/env python3
"""
purple-loop — MITRE ATT&CK purple team validation pipeline.

Given a technique ID:
  1. HuntForge generates hunt context + a starter Sigma rule
  2. AtomicLoop executes the atomic test and captures Windows events
  3. DriftWatch validates the Sigma rule against the captured events
  4. Results (fired/not-fired + gap analysis) are saved to output/

Usage
-----
Dry run (preview command, no execution):
    python main.py --technique T1059.001 --dry-run

Live execution (requires explicit --confirm):
    python main.py --technique T1059.001 --confirm

Specify test number:
    python main.py --technique T1059.001 --test 2 --confirm

Pass input arguments to the atomic test:
    python main.py --technique T1059.001 --confirm --arg target_url=http://127.0.0.1:8080

Skip HuntForge (provide your own Sigma rule):
    python main.py --technique T1059.001 --confirm --sigma /path/to/rule.yml

Custom config:
    python main.py --technique T1059.001 --confirm --config /path/to/config.yaml
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
logger = logging.getLogger("purple-loop")

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULTS = {
    "huntforge_url":   "http://127.0.0.1:5007",
    "atomicloop_url":  "http://127.0.0.1:5011",
    "driftwatch_url":  "http://127.0.0.1:5008",
    "output_dir":      os.path.join(os.path.dirname(__file__), "output"),
    "timeout":         60,
    "exec_timeout":    30,
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
# Step 1 — HuntForge: get hunt context + Sigma rule
# ---------------------------------------------------------------------------

def get_huntforge_context(technique_id: str, huntforge_url: str, timeout: int) -> tuple[str | None, dict | None]:
    """
    POST to HuntForge /api/playbook/generate.
    Returns (sigma_rule_yaml, playbook_dict) or (None, None) on failure.
    """
    url = huntforge_url.rstrip("/") + "/api/playbook/generate"
    logger.info("Requesting hunt playbook from HuntForge for %s…", technique_id)
    try:
        result = _post(url, {"technique_id": technique_id}, timeout)
        # Sigma rule lives at result["queries"]["sigma"] in the HuntForge
        # playbook response. Support a wrapped envelope as a fallback.
        sigma = (
            result.get("queries", {}).get("sigma")
            or result.get("playbook", {}).get("queries", {}).get("sigma")
        )
        if sigma and isinstance(sigma, dict):
            sigma = json.dumps(sigma)
        logger.info("HuntForge returned playbook (sigma rule present: %s)", bool(sigma))
        return sigma, result
    except urllib.error.URLError as exc:
        logger.warning("HuntForge unavailable (%s) — skipping playbook generation", exc)
        return None, None
    except Exception as exc:
        logger.warning("HuntForge error: %s — skipping playbook generation", exc)
        return None, None


def load_sigma_from_file(path: str) -> str:
    """Load a Sigma rule YAML from a file path."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# Step 2 — AtomicLoop: execute test + capture events
# ---------------------------------------------------------------------------

def run_atomic_test(
    technique_id: str,
    test_number: int,
    confirm: bool,
    dry_run: bool,
    input_arguments: dict,
    exec_timeout: int,
    atomicloop_url: str,
    http_timeout: int,
) -> dict | None:
    """
    POST to AtomicLoop /api/run.
    Returns the run result dict, or None on failure.
    """
    url = atomicloop_url.rstrip("/") + "/api/run"
    payload = {
        "technique_id":    technique_id,
        "test_number":     test_number,
        "confirm":         confirm,
        "dry_run":         dry_run,
        "capture_events":  True,
        "normalize":       True,
        "timeout":         exec_timeout,
        "input_arguments": input_arguments,
    }

    mode_label = "DRY RUN" if dry_run else "LIVE"
    logger.info(
        "AtomicLoop [%s] executing %s test #%d…",
        mode_label, technique_id, test_number,
    )
    try:
        result = _post(url, payload, http_timeout)
        if result.get("success"):
            logger.info(
                "AtomicLoop run complete: exit_code=%s, events=%d, run_id=%s",
                result.get("exit_code"),
                result.get("event_count", 0),
                result.get("run_id", ""),
            )
        else:
            logger.warning("AtomicLoop run failed: %s", result.get("error", "unknown error"))
        return result
    except urllib.error.URLError as exc:
        logger.error("AtomicLoop unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.error("AtomicLoop error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Step 3 — DriftWatch: validate Sigma rule against captured events
# ---------------------------------------------------------------------------

def validate_with_driftwatch(
    run_id: str | None,
    sigma_rule: str,
    events: list,
    driftwatch_url: str,
    atomicloop_url: str,
    timeout: int,
) -> dict | None:
    """
    POST to AtomicLoop /api/validate (which proxies through DriftWatch).
    Falls back to DriftWatch /api/validate directly if run_id is not available.
    Returns validation result dict, or None on failure.
    """
    if run_id:
        # Use AtomicLoop's validate endpoint which has the run stored
        url = f"{atomicloop_url.rstrip('/')}/api/validate"
        payload = {"run_id": run_id, "sigma_rule": sigma_rule}
        logger.info("Validating via AtomicLoop /api/validate (run_id=%s)…", run_id)
    else:
        url = driftwatch_url.rstrip("/") + "/api/validate"
        payload = {
            "rules_yaml":        sigma_rule,
            "events_json":       json.dumps(events),
            "time_window_hours": 1,
        }
        logger.info("Validating directly via DriftWatch /api/validate…")

    try:
        result = _post(url, payload, timeout)
        fired  = result.get("detection_fired", False)
        count  = result.get("match_count", 0)
        logger.info("Validation result: fired=%s, matched_events=%d", fired, count)
        return result
    except urllib.error.URLError as exc:
        logger.warning("Validation endpoint unavailable: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Validation error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Step 4 — Save report
# ---------------------------------------------------------------------------

def save_report(
    output_dir: str,
    technique_id: str,
    test_number: int,
    dry_run: bool,
    run_result: dict | None,
    validation_result: dict | None,
    playbook: dict | None,
    sigma_rule: str | None,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tname = technique_id.replace(".", "_")
    fname = f"purple_loop_{tname}_test{test_number}_{ts}.json"
    fpath = os.path.join(output_dir, fname)

    detection_fired = None
    if validation_result:
        detection_fired = validation_result.get("detection_fired")

    report = {
        "loop_id":          f"purple-loop-{ts}",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "technique_id":     technique_id,
        "test_number":      test_number,
        "dry_run":          dry_run,
        "detection_fired":  detection_fired,
        "huntforge_playbook": playbook,
        "sigma_rule":       sigma_rule,
        "atomic_run":       run_result,
        "validation":       validation_result,
    }

    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    logger.info("Report saved: %s", fpath)
    return fpath


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(
    technique_id: str,
    test_number: int,
    dry_run: bool,
    run_result: dict | None,
    validation_result: dict | None,
    report_path: str,
) -> None:
    width = 62
    print("\n" + "=" * width)
    print("  PURPLE-LOOP SUMMARY")
    print("=" * width)
    print(f"  Technique   : {technique_id}  (test #{test_number})")
    print(f"  Mode        : {'DRY RUN (no execution)' if dry_run else 'LIVE'}")

    if run_result:
        if run_result.get("success"):
            print(f"  Exit code   : {run_result.get('exit_code', 'N/A')}")
            print(f"  Events      : {run_result.get('event_count', 0)} captured")
            print(f"  Duration    : {run_result.get('duration_ms', 0)} ms")
        else:
            print(f"  Execution   : FAILED — {run_result.get('error', 'unknown')}")
    else:
        print("  Execution   : AtomicLoop unavailable")

    if validation_result:
        fired = validation_result.get("detection_fired")
        count = validation_result.get("match_count", 0)
        gap   = validation_result.get("gap_analysis", "")
        if fired is True:
            print(f"  Detection   : FIRED ({count} matched events)")
        elif fired is False:
            print(f"  Detection   : MISSED ({count} matched events)")
        else:
            print(f"  Detection   : {fired}")
        if gap:
            # Wrap gap analysis to fit width
            print(f"\n  Gap analysis:")
            for line in gap.split(". "):
                line = line.strip()
                if line:
                    print(f"    {line}.")
    else:
        print("  Detection   : Validation skipped (DriftWatch unavailable or no Sigma rule)")

    print(f"\n  Report      : {report_path}")
    print("=" * width + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="purple-loop — ATT&CK technique → execute → detect → validate"
    )
    p.add_argument(
        "--technique", required=True,
        help="MITRE ATT&CK technique ID (e.g. T1059.001)",
    )
    p.add_argument(
        "--test", type=int, default=1,
        help="Test number within the technique (default: 1)",
    )
    p.add_argument(
        "--confirm", action="store_true",
        help="Confirm live execution (required unless --dry-run)",
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Preview command without executing (always safe)",
    )
    p.add_argument(
        "--sigma", default=None,
        help="Path to a Sigma rule YAML file (skips HuntForge)",
    )
    p.add_argument(
        "--arg", action="append", default=[],
        metavar="KEY=VALUE",
        help="Input argument for the atomic test (repeatable)",
    )
    p.add_argument(
        "--output", default=None,
        help="Output directory for reports (default: ./output)",
    )
    p.add_argument(
        "--huntforge-url",  default=None,
        help="HuntForge base URL (default: http://127.0.0.1:5007)",
    )
    p.add_argument(
        "--atomicloop-url", default=None,
        help="AtomicLoop base URL (default: http://127.0.0.1:5011)",
    )
    p.add_argument(
        "--driftwatch-url", default=None,
        help="DriftWatch base URL (default: http://127.0.0.1:5008)",
    )
    p.add_argument(
        "--timeout",     type=int, default=None,
        help="HTTP request timeout in seconds (default: 60)",
    )
    p.add_argument(
        "--exec-timeout", type=int, default=None,
        help="Atomic test execution timeout in seconds (default: 30)",
    )
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = parse_args()
    logging.getLogger().setLevel(args.log_level)

    if not args.dry_run and not args.confirm:
        print(
            "ERROR: Live execution requires --confirm.\n"
            "       Use --dry-run to preview the command without executing.",
            file=sys.stderr,
        )
        sys.exit(1)

    cfg = dict(_DEFAULTS)
    if args.huntforge_url:
        cfg["huntforge_url"] = args.huntforge_url
    if args.atomicloop_url:
        cfg["atomicloop_url"] = args.atomicloop_url
    if args.driftwatch_url:
        cfg["driftwatch_url"] = args.driftwatch_url
    if args.output:
        cfg["output_dir"] = args.output
    if args.timeout:
        cfg["timeout"] = args.timeout
    if args.exec_timeout:
        cfg["exec_timeout"] = args.exec_timeout

    timeout      = int(cfg["timeout"])
    exec_timeout = int(cfg["exec_timeout"])
    output_dir   = cfg["output_dir"]

    # Parse --arg KEY=VALUE pairs
    input_arguments = {}
    for kv in args.arg:
        if "=" in kv:
            k, _, v = kv.partition("=")
            input_arguments[k.strip()] = v.strip()
        else:
            logger.warning("Ignoring malformed --arg %r (expected KEY=VALUE)", kv)

    # Step 1: Get Sigma rule
    sigma_rule = None
    playbook   = None

    if args.sigma:
        try:
            sigma_rule = load_sigma_from_file(args.sigma)
            logger.info("Loaded Sigma rule from %s", args.sigma)
        except Exception as exc:
            logger.error("Could not load Sigma rule from %s: %s", args.sigma, exc)
            sys.exit(1)
    else:
        sigma_rule, playbook = get_huntforge_context(
            args.technique, cfg["huntforge_url"], timeout
        )

    # Step 2: Execute atomic test
    run_result = run_atomic_test(
        technique_id    = args.technique,
        test_number     = args.test,
        confirm         = args.confirm,
        dry_run         = args.dry_run,
        input_arguments = input_arguments,
        exec_timeout    = exec_timeout,
        atomicloop_url  = cfg["atomicloop_url"],
        http_timeout    = timeout,
    )

    # Step 3: Validate if we have both a Sigma rule and captured events
    validation_result = None
    if sigma_rule and run_result:
        run_id = run_result.get("run_id")
        events = run_result.get("events", [])
        validation_result = validate_with_driftwatch(
            run_id, sigma_rule, events, cfg["driftwatch_url"], cfg["atomicloop_url"], timeout
        )

    # Step 4: Save report
    report_path = save_report(
        output_dir      = output_dir,
        technique_id    = args.technique,
        test_number     = args.test,
        dry_run         = args.dry_run,
        run_result      = run_result,
        validation_result = validation_result,
        playbook        = playbook,
        sigma_rule      = sigma_rule,
    )

    print_summary(
        args.technique, args.test, args.dry_run,
        run_result, validation_result, report_path,
    )


if __name__ == "__main__":
    main()
