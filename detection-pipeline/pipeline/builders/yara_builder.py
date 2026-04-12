"""
YaraForge rule builder.

Builds a YaraForge /api/generate payload from an EnrichedIOC and
POSTs it to YaraForge.

YaraForge /api/generate payload schema:
    {
        "name":        str    (valid YARA identifier),
        "description": str,
        "author":      str,
        "category":    str,
        "strings":     [{"type": "text"|"hex"|"regex", "value": str, "name": str}],
        "condition":   str
    }

Response:
    {"rule_content": str, "valid": bool, "error": str|null}

IOC-type → YARA string mapping:
  ip      → text string   category: network
  domain  → text string   category: network
  hash    → text string   category: malware
            (matches the hash string appearing in files/streams,
             e.g. in PowerShell logs or threat reports; a true binary
             byte-pattern rule requires the actual file content)
  url     → text string   category: network
"""

import logging
import re

import requests

from pipeline.models import EnrichedIOC, RuleResult

logger = logging.getLogger(__name__)

_TIMEOUT = 20

_TYPE_MAP = {
    "ip":     ("text", "network"),
    "domain": ("text", "network"),
    "hash":   ("text", "malware"),
    "url":    ("text", "network"),
}
_DEFAULT_MAP = ("text", "suspicious")


def _make_rule_name(ioc_type: str, value: str) -> str:
    """
    Produce a valid YARA identifier from the IOC type + value.

    YARA identifiers must match [a-zA-Z_][a-zA-Z0-9_]* and are capped at
    128 characters to stay readable.
    """
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", f"detect_{ioc_type}_{value}")
    # Ensure it doesn't start with a digit
    if sanitized[0].isdigit():
        sanitized = f"ioc_{sanitized}"
    return sanitized[:128]


def build_payload(enriched: EnrichedIOC, config: dict) -> dict:
    """Construct the JSON body for YaraForge POST /api/generate."""
    string_type, category = _TYPE_MAP.get(enriched.ioc_type, _DEFAULT_MAP)
    author = config.get("author", "detection-pipeline")
    rule_name = _make_rule_name(enriched.ioc_type, enriched.value)

    return {
        "name": rule_name,
        "description": (
            f"Detect threat intel {enriched.ioc_type} indicator: {enriched.value}. "
            f"Risk: {enriched.risk_level} ({enriched.risk_score}/100)."
        ),
        "author": author,
        "category": category,
        "strings": [
            {
                "type": string_type,
                "value": enriched.value,
                "name": f"{enriched.ioc_type}_ioc",
            }
        ],
        "condition": "any of them",
    }


def post(enriched: EnrichedIOC, yaraforge_url: str, config: dict) -> RuleResult:
    """POST to YaraForge /api/generate and return a RuleResult."""
    endpoint = yaraforge_url.rstrip("/") + "/api/generate"
    payload = build_payload(enriched, config)

    try:
        resp = requests.post(endpoint, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        return _fail(enriched, f"YaraForge unreachable at {endpoint}")
    except requests.exceptions.Timeout:
        return _fail(enriched, f"YaraForge timed out after {_TIMEOUT}s")
    except requests.exceptions.HTTPError as exc:
        return _fail(enriched, f"YaraForge HTTP {resp.status_code}: {exc}")
    except Exception as exc:
        return _fail(enriched, f"YaraForge unexpected error: {exc}")

    rule_content = data.get("rule_content", "")
    valid = data.get("valid", False)
    error = data.get("error") or ""

    if not rule_content:
        return _fail(enriched, f"YaraForge returned empty rule_content: {error}")

    if not valid and error:
        # Rule was generated but failed YARA validation — keep it but warn
        logger.warning(
            "    [yara]   WARN  %s — generated but invalid: %s", enriched.value, error
        )

    logger.info("    [yara]   OK  %s", enriched.value)
    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool="yara",
        success=True,
        content=rule_content,
        full_response=data,
    )


def _fail(enriched: EnrichedIOC, error: str) -> RuleResult:
    logger.warning("    [yara]   FAIL  %s — %s", enriched.value, error)
    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool="yara",
        success=False,
        error=error,
    )
