"""
ir-chain data models.

Lightweight dataclasses that act as the intermediate representation
between EndpointTriage output, log-analyzer alerts, and the SIREN
incident JSON schema.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class LogAlert:
    """A single alert produced by log-analyzer."""
    severity: str       # HIGH | MEDIUM | LOW
    rule: str           # e.g. "Brute Force Attempt"
    description: str
    source_ip: str = ""
    username: str = ""
    timestamp: str = ""


@dataclass
class TriageCase:
    """
    Represents one EndpointTriage output folder.

    Populated incrementally as each CSV is read; log_alerts are
    appended after the log-analyzer subprocess run.
    """
    case_path: str
    hostname: str
    folder_timestamp: str       # raw "YYYYMMDD_HHMMSS" from folder name

    system_info: dict = field(default_factory=dict)
    processes: List[dict] = field(default_factory=list)
    connections: List[dict] = field(default_factory=list)
    persistence_items: List[dict] = field(default_factory=list)
    scheduled_tasks: List[dict] = field(default_factory=list)
    recent_files: List[dict] = field(default_factory=list)
    log_alerts: List[LogAlert] = field(default_factory=list)
