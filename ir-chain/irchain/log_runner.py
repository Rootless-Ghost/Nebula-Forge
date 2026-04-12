"""
ir-chain log-analyzer runner.

EndpointTriage exports Windows event logs via Get-WinEvent with
Select-Object, so its Security.csv has the columns:

    TimeCreated, Id, LevelDisplayName, ProviderName, Message, RecordId, UserId

log-analyzer's parse_windows_log() expects:

    TimeCreated, EventID, SourceIP, TargetUserName, LogonType, Status

This module bridges that gap:
  1. adapt_security_csv() reads the ET Security.csv and writes a
     log-analyzer-compatible CSV to a temp directory, extracting
     SourceIP / TargetUserName / LogonType / Status from the rich
     Windows event Message field via regex.
  2. run_log_analyzer() calls the log-analyzer script as a subprocess
     and captures stdout.
  3. parse_log_analyzer_output() strips ANSI escape codes and parses
     the terminal output into a list of LogAlert objects.
  4. analyze_triage_logs() orchestrates all three steps for a single
     triage case folder.
"""

import csv
import logging
import os
import re
import subprocess
import sys
import tempfile
from typing import List, Optional

from irchain.models import LogAlert

logger = logging.getLogger(__name__)

# Strip ANSI colour codes produced by log-analyzer's terminal output
_ANSI_RE = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')


# ---------------------------------------------------------------------------
# Schema adapter
# ---------------------------------------------------------------------------

def _extract_event_fields(message: str, event_id: int) -> dict:
    """
    Parse a Windows event log Message string to extract the structured
    fields that log-analyzer needs.

    Windows event messages are localised, so we use flexible patterns
    that match both English variants seen in Security events.
    """
    result = {
        "source_ip": "Unknown",
        "username": "Unknown",
        "logon_type": "",
        "status": "Unknown",
    }

    # Status is deterministic from event ID
    if event_id == 4624:
        result["status"] = "Success"
    elif event_id == 4625:
        result["status"] = "Failure"

    if not message:
        return result

    # Logon Type (integer on the same line as "Logon Type:")
    m = re.search(r'Logon Type[:\s]+(\d+)', message)
    if m:
        result["logon_type"] = m.group(1)

    # Source IP — appears as "Source Network Address:" or "Source Address:"
    m = re.search(r'Source (?:Network )?Address[:\s]+([0-9a-fA-F.:]+)', message)
    if m:
        ip = m.group(1).strip()
        if ip not in ('-', '::1', '::'):
            result["source_ip"] = ip

    # Target username — prefer the "New Logon" section account name
    new_logon_match = re.search(
        r'New Logon:.*?Account Name[:\s]+(\S+)',
        message,
        re.DOTALL,
    )
    if new_logon_match:
        name = new_logon_match.group(1).strip()
        if name and name != '-':
            result["username"] = name
    else:
        # Fallback: first non-machine Account Name
        for name in re.findall(r'Account Name[:\s]+(\S+)', message):
            name = name.strip()
            if name and not name.endswith('$') and name != '-':
                result["username"] = name
                break

    return result


def adapt_security_csv(et_security_csv: str, temp_dir: str) -> Optional[str]:
    """
    Convert an EndpointTriage Security.csv to the format expected by
    log-analyzer and write it to temp_dir.

    Returns the path to the adapted CSV, or None if the source file
    does not exist or cannot be parsed.
    """
    if not os.path.exists(et_security_csv):
        logger.warning("Security.csv not found: %s", et_security_csv)
        return None

    os.makedirs(temp_dir, exist_ok=True)
    out_path = os.path.join(temp_dir, "adapted_security.csv")

    la_columns = ["TimeCreated", "EventID", "SourceIP", "TargetUserName", "LogonType", "Status"]

    rows_written = 0
    try:
        with open(et_security_csv, newline='', encoding='utf-8') as src, \
             open(out_path, 'w', newline='', encoding='utf-8') as dst:

            reader = csv.DictReader(src)
            fieldnames = reader.fieldnames or []
            writer = csv.DictWriter(dst, fieldnames=la_columns)
            writer.writeheader()

            for row in reader:
                # Detect format: log-analyzer native vs EndpointTriage WinEvent
                if 'EventID' in fieldnames:
                    # Already compatible — pass through directly
                    writer.writerow({
                        "TimeCreated": row.get("TimeCreated", ""),
                        "EventID": row.get("EventID", ""),
                        "SourceIP": row.get("SourceIP", row.get("IpAddress", "Unknown")),
                        "TargetUserName": row.get("TargetUserName", "Unknown"),
                        "LogonType": row.get("LogonType", ""),
                        "Status": row.get("Status", "Unknown"),
                    })
                else:
                    # EndpointTriage WinEvent format (Id, Message, …)
                    try:
                        event_id = int(row.get("Id", 0))
                    except ValueError:
                        event_id = 0

                    fields = _extract_event_fields(row.get("Message", ""), event_id)
                    writer.writerow({
                        "TimeCreated": row.get("TimeCreated", ""),
                        "EventID": event_id,
                        "SourceIP": fields["source_ip"],
                        "TargetUserName": fields["username"],
                        "LogonType": fields["logon_type"],
                        "Status": fields["status"],
                    })
                rows_written += 1

    except Exception as exc:
        logger.error("Failed to adapt Security.csv: %s", exc)
        return None

    logger.info("Adapted %d security events → %s", rows_written, out_path)
    return out_path if rows_written > 0 else None


# ---------------------------------------------------------------------------
# Subprocess runner
# ---------------------------------------------------------------------------

def run_log_analyzer(csv_path: str, python_exe: str, script_path: str) -> str:
    """
    Invoke log-analyzer as a subprocess against the given CSV file.

    Returns the combined stdout+stderr string.  Never raises — on
    failure an empty string is returned and the error is logged.
    """
    cmd = [python_exe, script_path, "--input", csv_path, "--type", "windows"]
    logger.info("Running log-analyzer: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout + result.stderr
        if result.returncode not in (0, 1):
            # log-analyzer exits 1 when it calls sys.exit(1) on parse errors
            logger.warning("log-analyzer exited %d", result.returncode)
        return output
    except FileNotFoundError:
        logger.error(
            "Python interpreter or log-analyzer script not found. "
            "Check log_analyzer_python and log_analyzer_script in config.yaml."
        )
        return ""
    except subprocess.TimeoutExpired:
        logger.error("log-analyzer timed out")
        return ""
    except Exception as exc:
        logger.error("log-analyzer subprocess error: %s", exc)
        return ""


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub('', text)


def parse_log_analyzer_output(stdout: str) -> List[LogAlert]:
    """
    Parse the terminal output of log-analyzer into LogAlert objects.

    Expected output shape (after stripping ANSI codes):

        ALERTS:

          1. [HIGH] Brute Force Attempt
             10 failed logins from 10.0.0.55 within 5 min (targeting: admin)
             Time: 2025-02-04 08:16:01
    """
    clean = _strip_ansi(stdout)
    alerts: List[LogAlert] = []

    # Locate the ALERTS block
    alerts_match = re.search(
        r'ALERTS:\s*\n(.*?)(?:\[\*\]\s*Analysis complete|$)',
        clean,
        re.DOTALL,
    )
    if not alerts_match:
        logger.debug("No ALERTS section found in log-analyzer output")
        return alerts

    block = alerts_match.group(1)

    # Split on numbered items ("  1. " … "  2. " …)
    # Use a lookahead so we keep each item's content together
    items = re.split(r'\n(?=\s{1,4}\d+\.)', block)

    for item in items:
        item = item.strip()
        if not item:
            continue

        # First line: "N. [SEVERITY] Rule Name"
        header = re.match(r'\d+\.\s+\[(\w+)\]\s+(.+)', item)
        if not header:
            continue

        severity = header.group(1).strip().upper()
        rule = header.group(2).strip()

        lines = [ln.strip() for ln in item.split('\n')]
        description = lines[1] if len(lines) > 1 else ""
        timestamp = ""

        for line in lines[2:]:
            if line.startswith("Time:"):
                timestamp = line[5:].strip()

        # Extract structured fields from the description text
        source_ip = ""
        ip_m = re.search(r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', description)
        if ip_m:
            source_ip = ip_m.group(1)

        username = ""
        # Matches "'jsmith'" or "targeting: jsmith, admin"
        user_m = re.search(r"'([^']+)'", description)
        if user_m:
            username = user_m.group(1)

        alerts.append(LogAlert(
            severity=severity,
            rule=rule,
            description=description,
            source_ip=source_ip,
            username=username,
            timestamp=timestamp,
        ))

    logger.info("Parsed %d alerts from log-analyzer output", len(alerts))
    return alerts


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def analyze_triage_logs(case_path: str, config: dict) -> List[LogAlert]:
    """
    Run the full log-analyzer pipeline against a triage case folder.

    Steps
    -----
    1. Locate Security.csv inside the case folder's eventlogs/ directory.
    2. Adapt it to the log-analyzer CSV schema.
    3. Invoke log-analyzer via subprocess.
    4. Parse and return the alerts.

    Returns an empty list if any step fails; errors are logged rather
    than raised so the rest of the pipeline can continue.
    """
    security_csv = os.path.join(case_path, "eventlogs", "Security.csv")
    temp_dir = config.get("temp_dir", os.path.join(case_path, ".irchain_tmp"))

    adapted = adapt_security_csv(security_csv, temp_dir)
    if not adapted:
        logger.warning(
            "No adapted Security.csv available for %s — skipping log-analyzer", case_path
        )
        return []

    python_exe = config.get("log_analyzer_python", sys.executable)
    script_path = config.get("log_analyzer_script", "")
    if not script_path:
        logger.error("log_analyzer_script not set in config")
        return []

    script_path = os.path.abspath(script_path)
    if not os.path.exists(script_path):
        logger.error("log-analyzer script not found: %s", script_path)
        return []

    raw_output = run_log_analyzer(adapted, python_exe, script_path)
    return parse_log_analyzer_output(raw_output)
