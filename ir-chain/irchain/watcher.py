"""
ir-chain filesystem watcher.

Monitors the configured EndpointTriage output directory for new case
folders.  A case is considered complete when EndpointTriage writes its
final file — triage_report.html.

Startup behaviour
-----------------
Before the live watcher starts, scan_existing() walks the triage output
path and returns any case folders that do not yet have the processed
marker file.  This lets ir-chain resume after a restart without
re-processing already-handled cases.

Live behaviour
--------------
A watchdog Observer watches the (non-recursive) triage output directory
for new sub-directory creation events.  When a folder matching the
pattern ``{HOSTNAME}_{YYYYMMDD_HHMMSS}`` appears, a background thread
polls for triage_report.html (up to REPORT_TIMEOUT seconds) and then
puts the case path into the shared queue.
"""

import logging
import os
import queue
import re
import threading
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

logger = logging.getLogger(__name__)

# Matches EndpointTriage output folder names: HOSTNAME_20260412_141500
CASE_FOLDER_RE = re.compile(r'^.+_\d{8}_\d{6}$')
REPORT_FILENAME = "triage_report.html"
REPORT_TIMEOUT = 300   # seconds to wait for the report to appear


def scan_existing(triage_output_path: str, processed_marker: str) -> list:
    """
    Return paths of unprocessed case folders that already exist on disk.

    Unprocessed means the folder matches the naming pattern and does
    not contain the processed_marker file.
    """
    found = []
    if not os.path.isdir(triage_output_path):
        logger.warning("Triage output path does not exist: %s", triage_output_path)
        return found

    for entry in os.scandir(triage_output_path):
        if not entry.is_dir():
            continue
        if not CASE_FOLDER_RE.match(entry.name):
            continue
        marker_path = os.path.join(entry.path, processed_marker)
        report_path = os.path.join(entry.path, REPORT_FILENAME)
        if os.path.exists(marker_path):
            logger.debug("Skipping already-processed case: %s", entry.name)
            continue
        if not os.path.exists(report_path):
            logger.debug("Skipping incomplete case (no report yet): %s", entry.name)
            continue
        logger.info("Found unprocessed existing case: %s", entry.name)
        found.append(entry.path)

    return found


class _TriageEventHandler(FileSystemEventHandler):
    """watchdog handler: detects new case directories."""

    def __init__(self, case_queue: queue.Queue, triage_output_path: str,
                 processed_marker: str) -> None:
        super().__init__()
        self._queue = case_queue
        self._base = os.path.realpath(triage_output_path)
        self._marker = processed_marker
        self._seen: set = set()

    def on_created(self, event) -> None:
        if not event.is_directory:
            return
        name = os.path.basename(event.src_path)
        if not CASE_FOLDER_RE.match(name):
            return
        if event.src_path in self._seen:
            return
        self._seen.add(event.src_path)
        logger.info("New triage case directory detected: %s", name)
        t = threading.Thread(
            target=self._wait_for_report,
            args=(event.src_path,),
            daemon=True,
        )
        t.start()

    def _wait_for_report(self, case_path: str) -> None:
        """Poll for triage_report.html, then enqueue the case path."""
        report = os.path.join(case_path, REPORT_FILENAME)
        deadline = time.monotonic() + REPORT_TIMEOUT
        while time.monotonic() < deadline:
            if os.path.exists(report):
                # Brief pause to let the file handle close on Windows
                time.sleep(1)
                logger.info("Triage report ready, queuing case: %s", case_path)
                self._queue.put(case_path)
                return
            time.sleep(3)
        logger.warning(
            "triage_report.html never appeared in %s after %ds — skipping",
            case_path, REPORT_TIMEOUT,
        )


def start_watcher(triage_output_path: str, case_queue: queue.Queue,
                  processed_marker: str) -> Observer:
    """
    Start a watchdog Observer on the triage output directory.

    Returns the running Observer so the caller can stop it on shutdown.
    """
    if not os.path.isdir(triage_output_path):
        logger.warning(
            "Triage output path does not exist yet: %s — watcher will "
            "still start but will not receive events until the path appears.",
            triage_output_path,
        )
        os.makedirs(triage_output_path, exist_ok=True)

    handler = _TriageEventHandler(case_queue, triage_output_path, processed_marker)
    observer = Observer()
    # Non-recursive: case folders are direct children of the base directory
    observer.schedule(handler, path=triage_output_path, recursive=False)
    observer.start()
    logger.info("Watcher started on: %s", triage_output_path)
    return observer
