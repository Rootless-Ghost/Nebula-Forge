"""
detection-pipeline IOC parser.

Accepts IOCs from two sources:
  --ioc VALUE   One or more inline values on the CLI (flag repeatable)
  --file PATH   A plain-text file with one IOC per line

File format rules:
  - Lines starting with '#' are comments and are ignored
  - Blank lines are ignored
  - Leading/trailing whitespace is stripped
  - Duplicate values (case-insensitive) are deduplicated; first occurrence wins

Returns a list of unique IOC value strings.  Type detection is left to
the enricher (Threat Intel Dashboard auto-detects type on lookup).
"""

import logging
import os
from typing import List, Optional

logger = logging.getLogger(__name__)


def parse_ioc_file(path: str) -> List[str]:
    """
    Read IOCs from a plain-text file.

    Lines beginning with '#' and blank lines are skipped.
    Returns a list of stripped IOC strings (no deduplication at this stage).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"IOC file not found: {path}")

    iocs: List[str] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            iocs.append(line)
            logger.debug("  [file] line %d: %s", lineno, line)

    logger.info("Read %d IOC(s) from %s", len(iocs), path)
    return iocs


def collect_iocs(
    inline: Optional[List[str]],
    file_path: Optional[str],
) -> List[str]:
    """
    Merge inline CLI IOCs and file-sourced IOCs into a single deduplicated list.

    Parameters
    ----------
    inline : list of str or None
        Values passed via ``--ioc`` on the command line.
    file_path : str or None
        Path passed via ``--file`` on the command line.

    Returns
    -------
    list of str
        Unique IOC values in the order first encountered.
    """
    raw: List[str] = []

    if inline:
        for v in inline:
            v = v.strip()
            if v:
                raw.append(v)

    if file_path:
        raw.extend(parse_ioc_file(file_path))

    # Deduplicate preserving order; case-insensitive key
    seen: set = set()
    unique: List[str] = []
    for v in raw:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            unique.append(v)
        else:
            logger.debug("Duplicate IOC ignored: %s", v)

    logger.info(
        "Collected %d unique IOC(s) (%d inline, %d from file, %d duplicates removed)",
        len(unique),
        len(inline) if inline else 0,
        len(raw) - (len(inline) if inline else 0),
        len(raw) - len(unique),
    )
    return unique
