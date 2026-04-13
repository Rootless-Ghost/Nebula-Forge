"""
ir-chain SIREN client.

POSTs a pre-built incident JSON payload to SIREN's /api/generate endpoint
and persists the response (Markdown + JSON) to the output directory.

If SIREN is unreachable the payload is saved as a fallback JSON file so no
data is lost; the operator can re-submit it manually once SIREN is running.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 30   # seconds


def post_to_siren(
    payload: dict,
    siren_url: str,
    output_dir: str,
    case_name: str,
) -> Optional[dict]:
    """
    POST the incident payload to ``{siren_url}/api/generate``.

    On success
    ----------
    - Writes ``{output_dir}/{incident_id}.md``  — Markdown report
    - Writes ``{output_dir}/{incident_id}.json`` — Full JSON export
    - Returns the parsed SIREN response dict.

    On failure
    ----------
    - Writes ``{output_dir}/fallback_{case_name}.json`` — the raw payload
      so it can be re-submitted once SIREN is available.
    - Returns None.
    """
    os.makedirs(output_dir, exist_ok=True)
    endpoint = siren_url.rstrip("/") + "/api/generate"

    try:
        logger.info("POSTing to SIREN: %s", endpoint)
        resp = requests.post(
            endpoint,
            json=payload,
            timeout=_TIMEOUT,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        logger.error(
            "SIREN is not reachable at %s — saving fallback payload", endpoint
        )
        _save_fallback(payload, output_dir, case_name)
        return None
    except requests.exceptions.Timeout:
        logger.error("SIREN request timed out after %ds — saving fallback payload", _TIMEOUT)
        _save_fallback(payload, output_dir, case_name)
        return None
    except requests.exceptions.HTTPError as exc:
        logger.error("SIREN returned HTTP %s: %s", resp.status_code, exc)
        _save_fallback(payload, output_dir, case_name)
        return None
    except Exception as exc:
        logger.error("Unexpected error POSTing to SIREN: %s", exc)
        _save_fallback(payload, output_dir, case_name)
        return None

    try:
        data = resp.json()
    except ValueError:
        logger.error("SIREN returned non-JSON response")
        _save_fallback(payload, output_dir, case_name)
        return None

    print("[DEBUG] SIREN raw response:", data)

    if not data.get("success"):
        logger.error("SIREN reported failure: %s", data.get("error", "unknown error"))
        _save_fallback(payload, output_dir, case_name)
        return None

    incident_id = data.get("incident_id", f"IR-UNKNOWN-{case_name}")
    _save_outputs(data, output_dir, incident_id)
    logger.info("SIREN report created: %s", incident_id)
    return data


def _save_outputs(data: dict, output_dir: str, incident_id: str) -> None:
    """Persist the Markdown and JSON exports from SIREN."""
    md_path = os.path.join(output_dir, f"{incident_id}.md")
    json_path = os.path.join(output_dir, f"{incident_id}.json")

    if data.get("markdown"):
        try:
            with open(md_path, "w", encoding="utf-8") as fh:
                fh.write(data["markdown"])
            logger.info("Saved Markdown report: %s", md_path)
        except OSError as exc:
            logger.warning("Could not write Markdown report: %s", exc)

    if data.get("json"):
        try:
            # data["json"] is already a JSON string from SIREN
            parsed = json.loads(data["json"]) if isinstance(data["json"], str) else data["json"]
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(parsed, fh, indent=2)
            logger.info("Saved JSON report: %s", json_path)
        except (OSError, ValueError) as exc:
            logger.warning("Could not write JSON report: %s", exc)


def _save_fallback(payload: dict, output_dir: str, case_name: str) -> None:
    """Save the raw payload so it can be re-submitted manually."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"fallback_{case_name}_{ts}.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        logger.info("Fallback payload saved: %s", path)
    except OSError as exc:
        logger.error("Could not save fallback payload: %s", exc)
