"""
detection-pipeline enricher.

Sends each IOC to the Threat Intel Dashboard POST /lookup endpoint and
returns a structured EnrichedIOC.

TID response schema
-------------------
{
    "ioc": str,
    "type": "ip" | "domain" | "hash" | "url",
    "timestamp": str,
    "risk_score": int (0–100),
    "risk_level": "CLEAN" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    "sources": {
        "virustotal": {...},
        "abuseipdb": {...}   # IP only
    },
    "demo_mode": bool
}

Errors are surfaced via EnrichedIOC.error rather than raised so the
caller can continue processing remaining IOCs.
"""

import logging
from typing import List

import requests

from pipeline.models import EnrichedIOC

logger = logging.getLogger(__name__)

_TIMEOUT = 15  # seconds


def enrich(ioc_value: str, tid_url: str) -> EnrichedIOC:
    """
    Call Threat Intel Dashboard /lookup for a single IOC.

    Parameters
    ----------
    ioc_value : str
        The raw indicator string (IP, domain, hash, or URL).
    tid_url : str
        Base URL of the running Threat Intel Dashboard
        (e.g. ``http://127.0.0.1:5001``).

    Returns
    -------
    EnrichedIOC
        Populated on success; ``error`` field set on failure.
    """
    endpoint = tid_url.rstrip("/") + "/lookup"
    try:
        resp = requests.post(
            endpoint,
            json={"ioc": ioc_value},
            timeout=_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        msg = f"Threat Intel Dashboard unreachable at {endpoint}"
        logger.error(msg)
        return _error_result(ioc_value, msg)
    except requests.exceptions.Timeout:
        msg = f"Threat Intel Dashboard timed out after {_TIMEOUT}s"
        logger.error(msg)
        return _error_result(ioc_value, msg)
    except requests.exceptions.HTTPError as exc:
        msg = f"Threat Intel Dashboard returned HTTP {resp.status_code}: {exc}"
        logger.error(msg)
        return _error_result(ioc_value, msg)
    except Exception as exc:
        msg = f"Unexpected error calling Threat Intel Dashboard: {exc}"
        logger.error(msg)
        return _error_result(ioc_value, msg)

    try:
        data = resp.json()
    except ValueError:
        return _error_result(ioc_value, "Threat Intel Dashboard returned non-JSON response")

    if "error" in data:
        msg = f"Threat Intel Dashboard error: {data['error']}"
        logger.warning("%s — %s", ioc_value, msg)
        return _error_result(ioc_value, msg)

    ioc_type = data.get("type", "unknown")
    risk_score = int(data.get("risk_score", 0))
    risk_level = data.get("risk_level", "CLEAN")
    demo_mode = bool(data.get("demo_mode", True))

    logger.info(
        "  %-50s  type=%-8s  score=%3d  level=%s%s",
        ioc_value,
        ioc_type,
        risk_score,
        risk_level,
        "  [demo]" if demo_mode else "",
    )

    return EnrichedIOC(
        value=ioc_value,
        ioc_type=ioc_type,
        risk_score=risk_score,
        risk_level=risk_level,
        sources=data.get("sources", {}),
        demo_mode=demo_mode,
    )


def enrich_all(ioc_values: List[str], tid_url: str) -> List[EnrichedIOC]:
    """Enrich a list of IOCs sequentially. Returns one EnrichedIOC per input."""
    logger.info("Enriching %d IOC(s) via Threat Intel Dashboard…", len(ioc_values))
    return [enrich(v, tid_url) for v in ioc_values]


def _error_result(value: str, error: str) -> EnrichedIOC:
    return EnrichedIOC(
        value=value,
        ioc_type="unknown",
        risk_score=0,
        risk_level="CLEAN",
        sources={},
        demo_mode=True,
        error=error,
    )
