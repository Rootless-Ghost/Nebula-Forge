"""
SnortForge rule builder.

Builds SnortForge /api/build (Snort 2) and /api/build/snort3 payloads
from an EnrichedIOC and POSTs both simultaneously.  Returns two
RuleResults per IOC (tool="snort2" and tool="snort3").

SnortRule dict schema (from SnortForge/snortforge/core/rule.py):
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port
    msg, sid, rev, classtype, priority, references
    content, content_nocase, content_negated,
    content_http_uri, content_http_header
    pcre, depth, offset, distance, within
    contents: [{"content", "nocase", "negated", "http_uri", ...}]
    flow, threshold_type/track/count/seconds, metadata

IOC-type routing:
  ip      → alert ip any any -> <ip> any
              No content match; the IP itself is the rule target
  domain  → alert tcp any any -> any any
              content: <domain>, nocase, flow:established
  hash    → alert tcp any any -> any any
              content: <hash_string>, flow:established
              (matches the hash literal in stream or log data)
  url     → alert tcp any any -> any 80,443
              Multi-content: netloc (nocase) + URI path (http_uri, nocase)
              Falls back to single content if URL has no parseable path

Snort 2 and Snort 3 rules share the same SID since they are written to
separate files and are never loaded simultaneously.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import urlparse

import requests

from pipeline.models import EnrichedIOC, RuleResult

logger = logging.getLogger(__name__)

_TIMEOUT = 20


def _base(enriched: EnrichedIOC, config: dict, rule_index: int) -> dict:
    """Shared fields for every Snort rule."""
    snort_cfg = config.get("snort", {})
    sid_base = int(snort_cfg.get("sid_base", 1000001))
    action = snort_cfg.get("action", "alert")
    return {
        "action": action,
        "sid": sid_base + rule_index,
        "rev": 1,
        "priority": 1,
        "classtype": "trojan-activity",
        "references": [],
        "metadata": "",
        # defaults — overridden below
        "protocol": "tcp",
        "src_ip": "any",
        "src_port": "any",
        "direction": "->",
        "dst_ip": "any",
        "dst_port": "any",
        "msg": f"THREAT-INTEL {enriched.ioc_type.upper()}: {enriched.value[:60]}",
        "flow": "",
        "content": "",
        "content_nocase": False,
        "content_negated": False,
        "content_http_uri": False,
        "content_http_header": False,
        "pcre": "",
        "depth": 0,
        "offset": 0,
        "distance": 0,
        "within": 0,
        "contents": [],
        "threshold_type": "",
        "threshold_track": "",
        "threshold_count": 0,
        "threshold_seconds": 0,
    }


def build_payload(enriched: EnrichedIOC, config: dict, rule_index: int) -> dict:
    """Construct the SnortRule dict for this IOC."""
    d = _base(enriched, config, rule_index)
    ioc_type = enriched.ioc_type
    value = enriched.value

    if ioc_type == "ip":
        d.update({
            "protocol": "ip",
            "dst_ip": value,
            "dst_port": "any",
            "flow": "",
        })

    elif ioc_type == "domain":
        d.update({
            "protocol": "tcp",
            "flow": "established",
            "content": value,
            "content_nocase": True,
        })

    elif ioc_type == "hash":
        # Match the literal hash string as it may appear in HTTP responses,
        # log streams, or malware download references.
        d.update({
            "protocol": "tcp",
            "flow": "established",
            "content": value,
            "content_nocase": False,
        })

    elif ioc_type == "url":
        parsed = urlparse(value)
        netloc = parsed.netloc or value
        path = parsed.path or "/"

        if netloc and path and path != "/":
            # Multi-content: host header match + URI path match
            d.update({
                "protocol": "tcp",
                "dst_port": "80,443",
                "flow": "to_server,established",
                "contents": [
                    {
                        "content": netloc,
                        "nocase": True,
                        "negated": False,
                        "http_uri": False,
                        "http_header": True,    # match in Host header
                        "depth": 0, "offset": 0, "distance": 0, "within": 0,
                    },
                    {
                        "content": path,
                        "nocase": True,
                        "negated": False,
                        "http_uri": True,
                        "http_header": False,
                        "depth": 0, "offset": 0, "distance": 0, "within": 0,
                    },
                ],
                "msg": f"THREAT-INTEL URL: {netloc}{path[:40]}",
            })
        else:
            # Fallback: single content match on the whole value
            d.update({
                "protocol": "tcp",
                "dst_port": "80,443",
                "flow": "to_server,established",
                "content": value,
                "content_nocase": True,
            })

    else:
        # Unknown type — generic content match
        d.update({
            "protocol": "tcp",
            "flow": "established",
            "content": value,
            "content_nocase": True,
        })

    return d


def _post_one(
    endpoint: str,
    payload: dict,
    enriched: EnrichedIOC,
    tool: str,
) -> RuleResult:
    """POST to one SnortForge endpoint and return a RuleResult."""
    try:
        resp = requests.post(endpoint, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        return _fail(enriched, tool, f"SnortForge unreachable at {endpoint}")
    except requests.exceptions.Timeout:
        return _fail(enriched, tool, f"SnortForge timed out after {_TIMEOUT}s")
    except requests.exceptions.HTTPError as exc:
        return _fail(enriched, tool, f"SnortForge HTTP {resp.status_code}: {exc}")
    except Exception as exc:
        return _fail(enriched, tool, f"SnortForge unexpected error: {exc}")

    if not data.get("success"):
        return _fail(enriched, tool, data.get("error", "SnortForge returned success=false"))

    rule_text = data.get("rule_text", "")
    logger.info("    [%s]  OK  %s", tool, enriched.value)
    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool=tool,
        success=True,
        content=rule_text,
        full_response=data,
    )


def post_both(
    enriched: EnrichedIOC,
    snortforge_url: str,
    config: dict,
    rule_index: int,
) -> List[RuleResult]:
    """
    POST to both /api/build (Snort 2) and /api/build/snort3 concurrently.
    Returns a list of two RuleResults (snort2, snort3).
    """
    base_url = snortforge_url.rstrip("/")
    payload = build_payload(enriched, config, rule_index)

    endpoints = {
        "snort2": base_url + "/api/build",
        "snort3": base_url + "/api/build/snort3",
    }

    results: List[RuleResult] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(_post_one, url, payload, enriched, tool): tool
            for tool, url in endpoints.items()
        }
        for future in as_completed(futures):
            results.append(future.result())

    return results


def _fail(enriched: EnrichedIOC, tool: str, error: str) -> RuleResult:
    logger.warning("    [%s]  FAIL  %s — %s", tool, enriched.value, error)
    return RuleResult(
        ioc_value=enriched.value,
        ioc_type=enriched.ioc_type,
        tool=tool,
        success=False,
        error=error,
    )
