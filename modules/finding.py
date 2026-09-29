from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Normalized vulnerability finding model used across the scanner and reports."""

    title: str
    severity: str = 'Informational'
    confidence: str = 'Medium'
    target: str = ''
    endpoint: str = ''
    parameter: str = ''
    method: str = 'GET'
    payload: str = ''
    request: str = ''
    response: str = ''
    evidence: list[str] = field(default_factory=list)
    description: str = ''
    impact: str = ''
    remediation: str = ''
    cwe: str = ''
    cve: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    status: str = 'open'
    category: str = ''
    source: str = 'scanner'
    detection_method: str = 'heuristic'
    cvss: float = 0.0
    cvss_vector: str = ''
    cvss_version: str = 'CVSS v3.1'
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.severity = self._normalize_severity(self.severity)
        self.confidence = self._normalize_confidence(self.confidence)
        self.evidence = list(self.evidence or [])
        self.cve = list(self.cve or [])
        self.references = list(self.references or [])

    @staticmethod
    def _normalize_severity(value: str) -> str:
        if not value:
            return 'Informational'
        value = value.strip().title()
        valid = {'Critical', 'High', 'Medium', 'Low', 'Informational'}
        return value if value in valid else 'Informational'

    @staticmethod
    def _normalize_confidence(value: str) -> str:
        if not value:
            return 'Medium'
        value = value.strip().title()
        valid = {'Confirmed', 'High', 'Medium', 'Low', 'Informational'}
        return value if value in valid else 'Medium'

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity,
            'confidence': self.confidence,
            'cvss': {
                'version': self.cvss_version,
                'score': float(self.cvss),
                'vector': self.cvss_vector,
            },
            'cwe': self.cwe,
            'cve': list(self.cve),
            'target': self.target,
            'endpoint': self.endpoint,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'request': self.request,
            'response': self.response,
            'evidence': list(self.evidence),
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'references': list(self.references),
            'detection_method': self.detection_method,
            'status': self.status,
            'source': self.source,
            'category': self.category,
            'raw': self.raw,
        }
