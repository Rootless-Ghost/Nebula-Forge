"""
detection-pipeline dispatcher.

For each EnrichedIOC that passes the risk threshold, fires the three
rule builders (SigmaForge, YaraForge, SnortForge) concurrently using a
thread pool and collects all results into a PipelineResult.

Thread pool strategy
--------------------
Each IOC spawns three concurrent tasks:
  - sigma_builder.post()
  - yara_builder.post()
  - snort_builder.post_both()   (internally fires Snort 2 + Snort 3 concurrently)

All four rule outputs (sigma, yara, snort2, snort3) are collected before
the PipelineResult is returned.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from pipeline.builders import sigma_builder, snort_builder, yara_builder
from pipeline.models import EnrichedIOC, PipelineResult, RuleResult

logger = logging.getLogger(__name__)


def dispatch(
    enriched: EnrichedIOC,
    config: dict,
    rule_index: int,
) -> PipelineResult:
    """
    Route one EnrichedIOC to all rule builders simultaneously.

    Parameters
    ----------
    enriched : EnrichedIOC
        A successfully enriched IOC above the risk threshold.
    config : dict
        Full pipeline configuration.
    rule_index : int
        Monotonically increasing index used for SID / rule-ID assignment.

    Returns
    -------
    PipelineResult
        Contains all RuleResults from all four tool calls.
    """
    sigmaforge_url = config.get("sigmaforge_url", "http://127.0.0.1:5000")
    yaraforge_url = config.get("yaraforge_url", "http://127.0.0.1:5002")
    snortforge_url = config.get("snortforge_url", "http://127.0.0.1:5003")

    all_results: List[RuleResult] = []

    def _run_sigma():
        return [sigma_builder.post(enriched, sigmaforge_url, config, rule_index)]

    def _run_yara():
        return [yara_builder.post(enriched, yaraforge_url, config)]

    def _run_snort():
        return snort_builder.post_both(enriched, snortforge_url, config, rule_index)

    tasks = [_run_sigma, _run_yara, _run_snort]

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fn): fn.__name__ for fn in tasks}
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as exc:
                task_name = futures[future]
                logger.error("Builder task %s raised: %s", task_name, exc, exc_info=True)

    return PipelineResult(enriched=enriched, rules=all_results)


def run_pipeline(
    enriched_iocs: List[EnrichedIOC],
    config: dict,
    risk_threshold: int,
) -> List[PipelineResult]:
    """
    Filter IOCs by risk threshold and dispatch each to all rule builders.

    Parameters
    ----------
    enriched_iocs : List[EnrichedIOC]
        All enriched IOCs from the enricher stage.
    config : dict
        Full pipeline configuration.
    risk_threshold : int
        Minimum risk_score (0–100) required to generate rules.
        IOCs below this threshold produce a skipped PipelineResult.

    Returns
    -------
    List[PipelineResult]
        One entry per input IOC (skipped ones have skipped=True).
    """
    results: List[PipelineResult] = []
    rule_index = 0

    for enriched in enriched_iocs:
        # Enrichment failure
        if not enriched.is_valid:
            results.append(PipelineResult(
                enriched=enriched,
                skipped=True,
                skip_reason=f"Enrichment failed: {enriched.error}",
            ))
            continue

        # Unknown IOC type — skip
        if enriched.ioc_type == "unknown":
            results.append(PipelineResult(
                enriched=enriched,
                skipped=True,
                skip_reason="Threat Intel Dashboard could not determine IOC type",
            ))
            logger.warning("Skipped (unknown type): %s", enriched.value)
            continue

        # Risk threshold filter
        if enriched.risk_score < risk_threshold:
            results.append(PipelineResult(
                enriched=enriched,
                skipped=True,
                skip_reason=(
                    f"Risk score {enriched.risk_score} below threshold {risk_threshold} "
                    f"({enriched.risk_level})"
                ),
            ))
            logger.info(
                "Skipped (below threshold %d): %s  score=%d  level=%s",
                risk_threshold,
                enriched.value,
                enriched.risk_score,
                enriched.risk_level,
            )
            continue

        logger.info(
            "Dispatching [%d]: %s  type=%s  score=%d  level=%s",
            rule_index,
            enriched.value,
            enriched.ioc_type,
            enriched.risk_score,
            enriched.risk_level,
        )

        result = dispatch(enriched, config, rule_index)
        results.append(result)
        rule_index += 1

    return results
