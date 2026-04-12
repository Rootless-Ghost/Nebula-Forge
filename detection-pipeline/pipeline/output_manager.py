"""
detection-pipeline output manager.

Saves all generated rules to an organised directory tree and writes a
summary.json manifest for the run.

Output directory layout
-----------------------
{output_dir}/{YYYYMMDD_HHMMSS}/
    summary.json
    ip/
        1_2_3_4/
            sigma.yml
            sigma_conversions.json
            rule.yar
            rule.snort2.rules
            rule.snort3.rules
    domain/
        evil_com/
            sigma.yml
            ...
    hash/
        <sha256>/
            ...
    url/
        evil_com_path_to_payload/
            ...
    filtered_out.json      # IOCs below threshold or with errors
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import List

from pipeline.models import PipelineResult, RuleResult

logger = logging.getLogger(__name__)

# File extensions per tool
_EXTENSIONS = {
    "sigma":  "sigma.yml",
    "yara":   "rule.yar",
    "snort2": "rule.snort2.rules",
    "snort3": "rule.snort3.rules",
}


def _sanitize(value: str) -> str:
    """Convert an IOC value to a filesystem-safe directory name."""
    # Replace runs of non-alphanumeric chars with underscore
    safe = re.sub(r"[^a-zA-Z0-9]", "_", value)
    # Collapse multiple underscores and strip leading/trailing underscores
    safe = re.sub(r"_+", "_", safe).strip("_")
    # Cap length so paths don't get ridiculous
    return safe[:80] or "ioc"


def _run_dir(base_output_dir: str) -> str:
    """Create and return a timestamped run directory."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base_output_dir, ts)
    os.makedirs(path, exist_ok=True)
    return path


def _ioc_dir(run_dir: str, ioc_type: str, ioc_value: str) -> str:
    """Create and return the per-IOC subdirectory."""
    path = os.path.join(run_dir, ioc_type, _sanitize(ioc_value))
    os.makedirs(path, exist_ok=True)
    return path


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def _write_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def save(
    pipeline_results: List[PipelineResult],
    base_output_dir: str,
) -> str:
    """
    Persist all rule files and the summary manifest.

    Parameters
    ----------
    pipeline_results : List[PipelineResult]
        All results returned by dispatcher.run_pipeline().
    base_output_dir : str
        Root output directory from config.

    Returns
    -------
    str
        Absolute path of the run directory that was created.
    """
    run_dir = _run_dir(base_output_dir)
    logger.info("Writing output to: %s", run_dir)

    summary_iocs = []
    filtered_out = []

    # ── Counts for summary header ──────────────────────────────────────────
    rule_counts = {t: 0 for t in _EXTENSIONS}
    rule_fails = {t: 0 for t in _EXTENSIONS}

    for pr in pipeline_results:
        enriched = pr.enriched

        if pr.skipped:
            filtered_out.append({
                "value": enriched.value,
                "ioc_type": enriched.ioc_type,
                "risk_score": enriched.risk_score,
                "risk_level": enriched.risk_level,
                "reason": pr.skip_reason,
            })
            continue

        ioc_type = enriched.ioc_type
        ioc_dir = _ioc_dir(run_dir, ioc_type, enriched.value)

        rule_files: dict = {}

        for rule in pr.rules:
            tool = rule.tool
            ext = _EXTENSIONS.get(tool, f"{tool}.txt")
            file_path = os.path.join(ioc_dir, ext)
            rel_path = os.path.relpath(file_path, run_dir)

            if rule.success and rule.content:
                _write(file_path, rule.content)
                rule_counts[tool] = rule_counts.get(tool, 0) + 1
                rule_files[tool] = {
                    "success": True,
                    "file": rel_path.replace("\\", "/"),
                }

                # For Sigma: also persist conversions as a separate JSON
                if tool == "sigma":
                    conversions = rule.full_response.get("conversions", {})
                    if conversions:
                        conv_path = os.path.join(ioc_dir, "sigma_conversions.json")
                        _write_json(conv_path, conversions)
                        rule_files["sigma_conversions"] = {
                            "success": True,
                            "file": os.path.relpath(conv_path, run_dir).replace("\\", "/"),
                        }
            else:
                rule_fails[tool] = rule_fails.get(tool, 0) + 1
                rule_files[tool] = {
                    "success": False,
                    "error": rule.error,
                }

        summary_iocs.append({
            "value": enriched.value,
            "ioc_type": ioc_type,
            "risk_score": enriched.risk_score,
            "risk_level": enriched.risk_level,
            "demo_mode": enriched.demo_mode,
            "directory": os.path.relpath(ioc_dir, run_dir).replace("\\", "/"),
            "rules": rule_files,
        })

    # ── filtered_out.json ─────────────────────────────────────────────────
    if filtered_out:
        _write_json(os.path.join(run_dir, "filtered_out.json"), filtered_out)

    # ── summary.json ──────────────────────────────────────────────────────
    processed = len(pipeline_results) - len(filtered_out)
    summary = {
        "run_directory": run_dir,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "input_iocs": len(pipeline_results),
            "processed": processed,
            "filtered_out": len(filtered_out),
        },
        "rules_generated": rule_counts,
        "rules_failed": rule_fails,
        "iocs": summary_iocs,
    }
    _write_json(os.path.join(run_dir, "summary.json"), summary)

    logger.info(
        "Run complete — %d IOC(s) processed, %d filtered out",
        processed,
        len(filtered_out),
    )
    logger.info(
        "Rules generated: sigma=%d  yara=%d  snort2=%d  snort3=%d",
        rule_counts.get("sigma", 0),
        rule_counts.get("yara", 0),
        rule_counts.get("snort2", 0),
        rule_counts.get("snort3", 0),
    )

    return run_dir
