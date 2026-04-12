"""
detection-pipeline data models.

Lightweight dataclasses representing each stage of the pipeline:
  IOC → EnrichedIOC → RuleResult → PipelineResult
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class IOC:
    """A raw indicator before enrichment."""
    value: str
    ioc_type: str = "unknown"   # ip | domain | hash | url | unknown


@dataclass
class EnrichedIOC:
    """An IOC after Threat Intel Dashboard lookup."""
    value: str
    ioc_type: str               # ip | domain | hash | url
    risk_score: int             # 0–100
    risk_level: str             # CLEAN | LOW | MEDIUM | HIGH | CRITICAL
    sources: dict               # raw sources block from TID response
    demo_mode: bool
    error: str = ""

    @property
    def is_valid(self) -> bool:
        return not self.error


@dataclass
class RuleResult:
    """The output of one rule-builder call for one IOC."""
    ioc_value: str
    ioc_type: str
    tool: str                   # sigma | yara | snort2 | snort3
    success: bool
    content: str = ""           # rule text (YAML, YARA, .rules)
    full_response: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class PipelineResult:
    """Aggregated result for one IOC across all tools."""
    enriched: EnrichedIOC
    rules: List[RuleResult] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
