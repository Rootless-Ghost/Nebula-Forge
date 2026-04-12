"""
SigmaForge rule builder.

Builds a SigmaForge /api/generate payload from an EnrichedIOC and
POSTs it to SigmaForge.  Returns a RuleResult containing the Sigma
YAML and all SIEM-backend conversions from the response.

IOC-type → log source mapping (derived from SigmaForge's LOG_SOURCES):
  ip      → network_connection  field: DestinationIp
  domain  → dns_query           field: QueryName
  hash    → process_creation    field: Hashes
  url     → proxy               field: c-uri

The response ``rule_yaml`` is stored in RuleResult.content.
The full response (including all backend conversions) is stored in
RuleResult.full_response so the output manager can persist them.
"""

import logging

import requests

from pipeline.models import EnrichedIOC, RuleResult

logger = logging.getLogger(__name__)

_TIMEOUT = 20

# IOC type → (log_source_key, detection_field, mitre_techniques, description_template)
_TYPE_MAP = {
    "ip": (
        "network_connection",
        "DestinationIp",
        ["T1071", "T1071.001"],
        "Detected outbound network connection to threat intel IP indicator",
    ),
    "domain": (
        "dns_query",
        "QueryName",
        ["T1071.004"],
        "Detected DNS query matching a threat intel domain indicator",
    ),
    "hash": (
        "process_creation",
        "Hashes",
        ["T1204.002"],
        "Detected process execution matching a threat intel file hash",
    ),
    "url": (
        "proxy",
        "c-uri",
        ["T1071.001"],
        "Detected HTTP request matching a threat intel URL indicator",
    ),
}

# Fallback when ioc_type is unknown
_DEFAULT_MAP = ("proxy", "c-uri", ["T1071"], "Detected activity matching a threat intel indicator")


def _safe_rule_name(value: str) -> str:
    """Return a short, printable version of the IOC value for use in rule titles."""
    return value[:80] if len(value) <= 80 else value[:77] + "..."


def build_payload(enriched: EnrichedIOC, config: dict, rule_index: int) -> dict:
    """Construct the JSON body for SigmaForge POST /api/generate."""
    log_source, detection_field, mitre, desc_tmpl = _TYPE_MAP.get(
        enriched.ioc_type, _DEFAULT_MAP
    )

    sigma_cfg = config.get("sigma", {})
    author = config.get("author", "detection-pipeline")
    level = sigma_cfg.get("level", "high")
    status = sigma_cfg.get("status", "experimental")
    rule_id_base = int(sigma_cfg.get("rule_id_base", 100001))
    group_name = sigma_cfg.get("group_name", "sigma_rules")

    title = (
        f"Threat Intel {enriched.ioc_type.upper()} IOC — "
        f"{_safe_rule_name(enriched.value)} "
        f"(score: {enriched.risk_score})"
    )

    return {
        "title": title,
        "description": (
            f"{desc_tmpl}. "
            f"Value: {enriched.value}. "
            f"Risk: {enriched.risk_level} ({enriched.risk_score}/100)."
        ),
        "log_source": log_source,
        "level": level,
        "status": status,
        "author": author,
        "selections": [
            {
                "name": "sel",
                "fields": [
                    {
                        "field": detection_field,
                        "modifier": "contains",
                        "values": [enriched.value],
                    }
                ],
            }
        ],
        "filters": [],
        "condition": "sel",
        "mitre_techniques": mitre,
        "falsepositives": ["Legitimate traffic to this indicator if confirmed clean"],
        "references": [],
        "rule_id": rule_id_base + rule_index,
        "group_name": group_name,
    }


def post(enriched: EnrichedIOC, sigmaforge_url: str, config: dict, rule_index: int) -> RuleResult:
    """POST to SigmaForge /api/generate and return a RuleResult."""
    endpoint = sigmaforge_url.rstrip("/") + "/api/generate"
    payload = build_payload(enriched, config, rule_index)

    try:
        resp = requests.post(endpoint, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        return _fail(enriched, f"SigmaForge unreachable at {endpoint}")
    except requests.exceptions.Timeout:
        return _fail(enriched, f"SigmaForge timed out after {_TIMEOUT}s")
    except requests.exceptions.HTTPError as exc:
        return _fail(enriched, f"SigmaForge HTTP {resp.status_code}: {exc}")
    except Exception as exc:
        return _fail(enriched, f"SigmaForge unexpected error: {exc}")

    if not data.get("success"):
        return _fail(enriched, data.get("error", "SigmaForge returned success=false"))

    rule_yaml = data.get("rule_yaml", "")
    logger.info("    [sigma]  OK  %s", enriched.value)

    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool="sigma",
        success=True,
        content=rule_yaml,
        full_response=data,
    )


def _fail(enriched: EnrichedIOC, error: str) -> RuleResult:
    logger.warning("    [sigma]  FAIL  %s — %s", enriched.value, error)
    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool="sigma",
        success=False,
        error=error,
    )
