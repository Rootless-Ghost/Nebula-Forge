"""
ir-chain transformer.

Reads all relevant CSVs from an EndpointTriage case folder, combines
that data with the log-analyzer alerts, and produces a JSON payload
matching SIREN's /api/generate schema:

    {
        "title", "severity", "category", "analyst",
        "description", "detection_date", "containment_date",
        "eradication_date", "recovery_date", "executive_summary",
        "timeline_events": [{"timestamp", "description", "source"}],
        "iocs":            [{"type", "value", "context"}],
        "affected_systems":[{"hostname", "ip_address", "impact"}],
        "recommendations": [str]
    }

CSV column reference (from Invoke-EndpointTriage.ps1)
------------------------------------------------------
system_info.csv        : Hostname, Domain, OSName, OSVersion, TriageTimestamp,
                         CurrentUser, TotalMemoryGB, Architecture, LastBoot, Uptime
running_processes.csv  : PID, PPID, Name, Path, CommandLine, Owner, SHA256,
                         CreationDate, WorkingSetMB, ThreadCount, HandleCount, Flags
tcp_connections.csv    : LocalAddress, LocalPort, RemoteAddress, RemotePort,
                         State, PID, ProcessName, ProcessPath, CreationTime
persistence_items.csv  : Category, Location, Name, Value, ATTACKRef
scheduled_tasks.csv    : TaskName, TaskPath, State, Author, Description,
                         Actions, Triggers, LastRunTime, NextRunTime,
                         LastResult, RunAsUser, RunLevel
recent_file_modifications.csv : FullPath, Name, Extension, SizeKB, Created,
                                 Modified, Accessed, Directory, SuspiciousExt, Hidden
"""

import csv
import ipaddress
import logging
import os
import re
from typing import Any, Dict, List, Optional

from irchain.models import LogAlert

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SIREN severity / category enumerations (from SIREN/src/report_engine.py)
# ---------------------------------------------------------------------------
SIREN_SEVERITIES = {"Low", "Medium", "High", "Critical"}
SIREN_CATEGORIES = {
    "Malware Incident",
    "Phishing Attack",
    "Unauthorized Access",
    "DDoS Attack",
    "Data Breach",
    "Insider Threat",
    "Web Application Attack",
    "Ransomware",
    "Other",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_csv(path: str) -> List[Dict[str, str]]:
    """Safely read a CSV file; return empty list if missing or unreadable."""
    if not os.path.exists(path):
        logger.debug("CSV not found, skipping: %s", path)
        return []
    try:
        with open(path, newline='', encoding='utf-8') as fh:
            return list(csv.DictReader(fh))
    except Exception as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return []


def _parse_folder_timestamp(raw: str) -> str:
    """
    Convert a folder timestamp ("YYYYMMDD_HHMMSS") to SIREN date format
    ("YYYY-MM-DD HH:MM:SS UTC").
    """
    try:
        date_part, time_part = raw.split("_")
        return (
            f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]} "
            f"{time_part[:2]}:{time_part[2:4]}:{time_part[4:6]} UTC"
        )
    except Exception:
        return raw


def _is_external_ip(addr: str) -> bool:
    """Return True if addr is a routable, non-loopback, non-private IPv4/IPv6 address."""
    try:
        ip = ipaddress.ip_address(addr)
        return not (ip.is_private or ip.is_loopback or ip.is_unspecified
                    or ip.is_link_local or ip.is_multicast)
    except ValueError:
        return False


def _flag_summary(flags_str: str) -> str:
    """Human-readable expansion of EndpointTriage process Flags field."""
    mapping = {
        "TEMP_EXEC": "executing from temp directory",
        "PUBLIC_DIR": "executing from public directory",
        "SUSPICIOUS_CLI": "suspicious command-line arguments detected",
        "OFFICE_CHILD": "spawned by Office application",
    }
    parts = [mapping.get(f.strip(), f.strip()) for f in flags_str.split(";") if f.strip()]
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Severity / category derivation
# ---------------------------------------------------------------------------

_ALERT_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _determine_severity(
    alerts: List[LogAlert],
    processes: List[dict],
    persistence: List[dict],
) -> str:
    """
    Derive a SIREN severity string from the combined evidence.

    Priority order: alert severity → suspicious process flags → persistence items.
    """
    max_alert_rank = max(
        (_ALERT_SEVERITY_RANK.get(a.severity.upper(), 0) for a in alerts),
        default=0,
    )

    flagged_proc_count = sum(1 for p in processes if p.get("Flags", "").strip())
    # High-risk persistence categories elevate severity
    high_risk_persistence = {"WMI Event Subscription", "IFEO Debugger", "AppInit_DLLs"}
    has_high_risk_persist = any(
        p.get("Category", "") in high_risk_persistence for p in persistence
    )

    if max_alert_rank >= 3 or has_high_risk_persist:
        return "High"
    if max_alert_rank == 2 or flagged_proc_count >= 3:
        return "Medium"
    if max_alert_rank == 1 or flagged_proc_count > 0 or persistence:
        return "Medium"
    return "Low"


def _determine_category(
    alerts: List[LogAlert],
    processes: List[dict],
    persistence: List[dict],
) -> str:
    """Classify the incident type from available evidence."""
    alert_rules = {a.rule for a in alerts}
    process_flags = " ".join(p.get("Flags", "") for p in processes)
    persist_categories = {p.get("Category", "") for p in persistence}

    # Malware indicators take priority
    if (
        "OFFICE_CHILD" in process_flags
        or "SUSPICIOUS_CLI" in process_flags
        or "WMI Event Subscription" in persist_categories
        or "IFEO Debugger" in persist_categories
        or "AppInit_DLLs" in persist_categories
    ):
        return "Malware Incident"

    if any(r in alert_rules for r in ("Brute Force Attempt", "Off-Hours Login",
                                       "Privilege Escalation", "Account Lockout")):
        return "Unauthorized Access"

    return "Other"


# ---------------------------------------------------------------------------
# IOC extraction
# ---------------------------------------------------------------------------

def _build_iocs(
    connections: List[dict],
    processes: List[dict],
    alerts: List[LogAlert],
) -> List[dict]:
    """
    Extract Indicators of Compromise from triage artefacts.

    Sources
    -------
    - External remote addresses from established TCP connections
    - SHA256 hashes of flagged processes
    - Source IPs from log-analyzer brute-force / privilege-escalation alerts
    - Usernames from privilege-escalation alerts
    """
    iocs: List[dict] = []
    seen: set = set()

    def _add(ioc_type: str, value: str, context: str) -> None:
        key = (ioc_type, value)
        if key not in seen and value and value not in ("-", "Unknown", ""):
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value, "context": context})

    # External TCP connections
    for conn in connections:
        remote = conn.get("RemoteAddress", "").strip()
        state = conn.get("State", "").strip()
        if state == "Established" and _is_external_ip(remote):
            port = conn.get("RemotePort", "")
            proc = conn.get("ProcessName", "unknown")
            _add(
                "IP Address",
                remote,
                f"Established TCP connection on port {port} (process: {proc})",
            )

    # Flagged process hashes
    valid_hash_re = re.compile(r'^[0-9a-fA-F]{64}$')
    for proc in processes:
        flags = proc.get("Flags", "").strip()
        sha256 = proc.get("SHA256", "").strip()
        if flags and valid_hash_re.match(sha256):
            name = proc.get("Name", "unknown")
            _add(
                "File Hash (SHA256)",
                sha256,
                f"SHA256 of flagged process '{name}' — {_flag_summary(flags)}",
            )

    # Alert-derived IOCs
    for alert in alerts:
        if alert.source_ip and alert.source_ip not in ("Unknown", ""):
            _add(
                "IP Address",
                alert.source_ip,
                f"Source IP from log-analyzer alert: {alert.rule}",
            )
        if alert.rule == "Privilege Escalation" and alert.username not in ("Unknown", ""):
            _add(
                "Username",
                alert.username,
                "Account involved in privilege-escalation event",
            )

    return iocs


# ---------------------------------------------------------------------------
# Timeline construction
# ---------------------------------------------------------------------------

def _ts(raw: str) -> str:
    """Normalise a raw timestamp string; return as-is if unparseable."""
    raw = raw.strip()
    if not raw or raw in ("-", "N/A"):
        return ""
    return raw


def _build_timeline(
    triage_timestamp: str,
    hostname: str,
    alerts: List[LogAlert],
    processes: List[dict],
    persistence: List[dict],
    scheduled_tasks: List[dict],
    recent_files: List[dict],
) -> List[dict]:
    """
    Assemble the incident timeline from all available evidence sources.

    Events are built in this order (SIREN sorts them chronologically):
      1. Triage collection completed
      2. log-analyzer alerts
      3. Flagged process detections
      4. Suspicious persistence items
      5. Suspicious scheduled tasks
      6. Suspicious recent files
    """
    events: List[dict] = []

    def _event(ts: str, desc: str, source: str) -> None:
        events.append({"timestamp": ts, "description": desc, "source": source})

    _event(
        triage_timestamp,
        f"EndpointTriage artifact collection completed on host {hostname}",
        "EndpointTriage",
    )

    for alert in alerts:
        ts = _ts(alert.timestamp) or triage_timestamp
        _event(ts, f"[{alert.severity}] {alert.rule}: {alert.description}", "log-analyzer")

    for proc in processes:
        flags = proc.get("Flags", "").strip()
        if not flags:
            continue
        name = proc.get("Name", "?")
        path = proc.get("Path", "N/A")
        pid = proc.get("PID", "?")
        created = _ts(proc.get("CreationDate", "")) or triage_timestamp
        _event(
            created,
            f"Suspicious process: {name} (PID {pid}) — {_flag_summary(flags)} | path: {path}",
            "EndpointTriage / Processes",
        )

    high_risk = {"WMI Event Subscription", "IFEO Debugger", "AppInit_DLLs"}
    for item in persistence:
        category = item.get("Category", "")
        name = item.get("Name", "?")
        location = item.get("Location", "?")
        attack = item.get("ATTACKRef", "")
        severity_tag = "HIGH-RISK " if category in high_risk else ""
        _event(
            triage_timestamp,
            f"{severity_tag}Persistence item [{category}]: '{name}' at {location}"
            + (f" ({attack})" if attack else ""),
            "EndpointTriage / Persistence",
        )

    for task in scheduled_tasks:
        state = task.get("State", "")
        actions = task.get("Actions", "")
        if state == "Ready" and actions and "N/A" not in actions:
            _event(
                triage_timestamp,
                f"Non-Microsoft scheduled task: '{task.get('TaskName','?')}' "
                f"— actions: {actions}",
                "EndpointTriage / ScheduledTasks",
            )

    for f in recent_files:
        if str(f.get("SuspiciousExt", "")).strip().lower() in ("true", "1"):
            _event(
                _ts(f.get("Modified", "")) or triage_timestamp,
                f"Suspicious file modified: {f.get('FullPath', '?')} "
                f"({f.get('SizeKB', '?')} KB)",
                "EndpointTriage / FileSystem",
            )

    return events


# ---------------------------------------------------------------------------
# Affected systems
# ---------------------------------------------------------------------------

def _build_affected_systems(
    system_info: dict,
    connections: List[dict],
) -> List[dict]:
    """
    Build the affected_systems list.

    The primary entry is always the triaged host itself.  IP address is
    derived from the system_info or inferred from local TCP addresses.
    """
    hostname = system_info.get("Hostname", "UNKNOWN")

    # Try to find a non-loopback local IP from TCP connections
    local_ip = ""
    for conn in connections:
        local = conn.get("LocalAddress", "").strip()
        try:
            ip = ipaddress.ip_address(local)
            if not ip.is_loopback and not ip.is_unspecified:
                local_ip = local
                break
        except ValueError:
            continue

    os_name = system_info.get("OSName", "")
    uptime = system_info.get("Uptime", "")
    impact = f"Triaged host. OS: {os_name}. Uptime: {uptime}." if os_name else "Triaged host."

    return [{"hostname": hostname, "ip_address": local_ip, "impact": impact}]


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

_BASE_RECOMMENDATIONS = [
    "Review and validate all identified IOCs against threat intelligence feeds",
    "Isolate the affected host if active compromise indicators are confirmed",
    "Force password reset for any accounts flagged in log-analyzer alerts",
    "Capture a full memory image before rebooting the system",
    "Preserve all EndpointTriage artefacts (CSVs, HTML report) as evidence",
]

_RULE_RECOMMENDATIONS: Dict[str, List[str]] = {
    "Brute Force Attempt": [
        "Block the source IP(s) at the perimeter firewall and host-based firewall",
        "Enable account lockout policy if not already enforced (recommend: 5 attempts / 15 min)",
        "Review VPN and RDP exposure — disable if not required from external networks",
    ],
    "Off-Hours Login": [
        "Verify the legitimacy of the off-hours login with the account owner",
        "Enable conditional-access or MFA requirements for after-hours logons",
    ],
    "Privilege Escalation": [
        "Immediately audit group membership changes on the affected host",
        "Review who has local administrator rights — reduce to least-privilege",
        "Enable and monitor Windows Event IDs 4728, 4732, 4756 in your SIEM",
    ],
    "Account Lockout": [
        "Investigate the source of repeated failed authentications triggering lockouts",
        "Check for credential-stuffing tools or scheduled tasks using stale credentials",
    ],
}

_FLAG_RECOMMENDATIONS: Dict[str, str] = {
    "OFFICE_CHILD": (
        "Enable Attack Surface Reduction (ASR) rules to block Office macro child processes "
        "(GUID: d4f940ab-401b-4efc-aadc-ad5f3c50688a)"
    ),
    "SUSPICIOUS_CLI": (
        "Investigate encoded/obfuscated PowerShell command lines — consider enabling "
        "PowerShell ScriptBlock Logging (Event ID 4104)"
    ),
    "TEMP_EXEC": (
        "Block execution from user temp directories via AppLocker or Windows Defender "
        "Application Control (WDAC)"
    ),
    "PUBLIC_DIR": (
        "Restrict write and execute permissions on C:\\Users\\Public"
    ),
}

_PERSIST_RECOMMENDATIONS: Dict[str, str] = {
    "WMI Event Subscription": (
        "Enumerate and remove all WMI event subscriptions; monitor WMI activity with "
        "Sysmon Event IDs 19/20/21 (T1546.003)"
    ),
    "IFEO Debugger": (
        "Remove unauthorised Image File Execution Options debugger entries; "
        "legitimate software should not require IFEO hijacking (T1546.012)"
    ),
    "AppInit_DLLs": (
        "Remove unauthorised AppInit_DLLs values; set LoadAppInit_DLLs=0 if not needed "
        "(T1546.010)"
    ),
}


def _build_recommendations(
    alerts: List[LogAlert],
    processes: List[dict],
    persistence: List[dict],
) -> List[str]:
    recs: List[str] = list(_BASE_RECOMMENDATIONS)
    seen: set = set()

    def _add(rec: str) -> None:
        if rec not in seen:
            seen.add(rec)
            recs.append(rec)

    for alert in alerts:
        for rec in _RULE_RECOMMENDATIONS.get(alert.rule, []):
            _add(rec)

    all_flags = " ".join(p.get("Flags", "") for p in processes)
    for flag, rec in _FLAG_RECOMMENDATIONS.items():
        if flag in all_flags:
            _add(rec)

    persist_cats = {p.get("Category", "") for p in persistence}
    for cat, rec in _PERSIST_RECOMMENDATIONS.items():
        if cat in persist_cats:
            _add(rec)

    return recs


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _build_executive_summary(
    hostname: str,
    triage_timestamp: str,
    severity: str,
    category: str,
    alerts: List[LogAlert],
    processes: List[dict],
    persistence: List[dict],
    connections: List[dict],
) -> str:
    high = sum(1 for a in alerts if a.severity.upper() == "HIGH")
    medium = sum(1 for a in alerts if a.severity.upper() == "MEDIUM")
    low = sum(1 for a in alerts if a.severity.upper() == "LOW")
    flagged_procs = sum(1 for p in processes if p.get("Flags", "").strip())
    external_conns = sum(
        1 for c in connections
        if c.get("State", "") == "Established" and _is_external_ip(c.get("RemoteAddress", ""))
    )

    alert_summary = (
        f"{len(alerts)} alert(s) generated (HIGH: {high}, MEDIUM: {medium}, LOW: {low})"
        if alerts
        else "No log-based alerts generated"
    )

    proc_summary = (
        f"{flagged_procs} process(es) with suspicious characteristics were identified"
        if flagged_procs
        else "No processes with suspicious flags were identified"
    )

    persist_summary = (
        f"{len(persistence)} persistence mechanism(s) were catalogued across registry "
        "run keys, services, startup folder, WMI subscriptions, and IFEO"
        if persistence
        else "No persistence items were found"
    )

    conn_summary = (
        f"{external_conns} established connection(s) to external IP address(es) were recorded"
        if external_conns
        else "No established external TCP connections were observed at collection time"
    )

    return (
        f"An automated triage of host {hostname} was completed at {triage_timestamp} "
        f"using EndpointTriage. Preliminary analysis classifies this as a {severity}-severity "
        f"{category} event. {alert_summary}. {proc_summary}. {persist_summary}. "
        f"{conn_summary}. This report was generated automatically by ir-chain and should "
        f"be reviewed and enriched by a qualified analyst before distribution."
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def build_siren_payload(
    case_path: str,
    alerts: List[LogAlert],
    config: dict,
) -> dict:
    """
    Build a SIREN-compatible JSON payload from an EndpointTriage case folder
    and the log-analyzer alerts produced for that case.

    Parameters
    ----------
    case_path : str
        Absolute path to the EndpointTriage output folder
        (e.g. ``/data/TriageOutput/WORKSTATION01_20260412_141500``).
    alerts : List[LogAlert]
        Parsed alerts returned by ``log_runner.analyze_triage_logs()``.
    config : dict
        Loaded ir-chain configuration.

    Returns
    -------
    dict
        Ready to POST to SIREN's ``/api/generate`` endpoint.
    """
    # ---- Parse folder name ----
    folder_name = os.path.basename(case_path.rstrip("/\\"))
    # HOSTNAME_YYYYMMDD_HHMMSS  →  split on last two underscores
    parts = folder_name.rsplit("_", 2)
    if len(parts) == 3:
        hostname, date_part, time_part = parts
        folder_ts_raw = f"{date_part}_{time_part}"
    else:
        hostname = folder_name
        folder_ts_raw = ""

    triage_timestamp = _parse_folder_timestamp(folder_ts_raw) if folder_ts_raw else ""

    # ---- Load CSVs ----
    system_rows = _read_csv(os.path.join(case_path, "system", "system_info.csv"))
    system_info = system_rows[0] if system_rows else {}

    # Use TriageTimestamp from system_info if available (more accurate than folder name)
    if system_info.get("TriageTimestamp"):
        triage_timestamp = system_info["TriageTimestamp"].strip() + " UTC"

    processes = _read_csv(os.path.join(case_path, "processes", "running_processes.csv"))
    connections = _read_csv(os.path.join(case_path, "network", "tcp_connections.csv"))
    persistence = _read_csv(os.path.join(case_path, "persistence", "persistence_items.csv"))
    scheduled_tasks = _read_csv(os.path.join(case_path, "persistence", "scheduled_tasks.csv"))
    recent_files = _read_csv(os.path.join(case_path, "filesystem", "recent_file_modifications.csv"))

    logger.info(
        "Case %s: %d processes, %d connections, %d persistence items, %d alerts",
        folder_name, len(processes), len(connections), len(persistence), len(alerts),
    )

    # ---- Derive report fields ----
    hostname = system_info.get("Hostname", hostname)
    severity = _determine_severity(alerts, processes, persistence)
    category = _determine_category(alerts, processes, persistence)
    analyst = config.get("analyst", "ir-chain (automated)")

    title = f"Endpoint Triage: {hostname} — {triage_timestamp or folder_name}"
    description = (
        f"Automated triage of host {hostname}. "
        f"OS: {system_info.get('OSName', 'N/A')}  "
        f"Uptime: {system_info.get('Uptime', 'N/A')}  "
        f"Triage user: {system_info.get('TriageUser', 'N/A')}"
    )

    timeline = _build_timeline(
        triage_timestamp,
        hostname,
        alerts,
        processes,
        persistence,
        scheduled_tasks,
        recent_files,
    )

    iocs = _build_iocs(connections, processes, alerts)
    affected = _build_affected_systems(system_info, connections)
    recommendations = _build_recommendations(alerts, processes, persistence)
    exec_summary = _build_executive_summary(
        hostname, triage_timestamp, severity, category,
        alerts, processes, persistence, connections,
    )

    return {
        "title": title,
        "severity": severity,
        "category": category,
        "analyst": analyst,
        "description": description,
        "detection_date": triage_timestamp,
        "containment_date": "",
        "eradication_date": "",
        "recovery_date": "",
        "executive_summary": exec_summary,
        "timeline_events": timeline,
        "iocs": iocs,
        "affected_systems": affected,
        "recommendations": recommendations,
    }
