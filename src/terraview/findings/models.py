from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_name: str
    file_path: str
    line_number: Optional[int] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    remediation: Optional[str] = None
    blast_radius: list[str] = field(default_factory=list)
    reasoning: Optional[str] = None
    source: str = "static"  # static | graph | llm

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "remediation": self.remediation,
            "blast_radius": self.blast_radius,
            "reasoning": self.reasoning,
            "source": self.source,
        }
