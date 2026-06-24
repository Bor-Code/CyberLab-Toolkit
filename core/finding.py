from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

from core.constants import SEVERITY_INFO, SEVERITY_LEVELS


def get_utc_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_severity(severity):
    value = str(severity).lower().strip()

    if value not in SEVERITY_LEVELS:
        return SEVERITY_INFO

    return value


@dataclass
class Finding:
    title: str
    description: str
    severity: str = SEVERITY_INFO
    category: str = "general"
    source_module: str = "unknown"
    mitre_technique: str = "N/A"
    evidence: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(default_factory=get_utc_timestamp)

    def __post_init__(self):
        self.severity = normalize_severity(self.severity)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(
            title=data.get("title", "Untitled finding"),
            description=data.get("description", ""),
            severity=data.get("severity", SEVERITY_INFO),
            category=data.get("category", "general"),
            source_module=data.get("source_module", "unknown"),
            mitre_technique=data.get("mitre_technique", "N/A"),
            evidence=list(data.get("evidence", [])),
            recommendations=list(data.get("recommendations", [])),
            finding_id=data.get("finding_id", str(uuid4())),
            timestamp=data.get("timestamp", get_utc_timestamp()),
        )


def create_finding(
    title,
    description,
    severity=SEVERITY_INFO,
    category="general",
    source_module="unknown",
    mitre_technique="N/A",
    evidence=None,
    recommendations=None,
):
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=category,
        source_module=source_module,
        mitre_technique=mitre_technique,
        evidence=evidence or [],
        recommendations=recommendations or [],
    )