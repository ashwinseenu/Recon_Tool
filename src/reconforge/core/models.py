"""Result models shared by modules, reporting and the dashboard."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.value]


@dataclass
class Finding:
    title: str
    detail: str = ""
    severity: Severity = Severity.INFO
    data: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"title": self.title, "detail": self.detail, "severity": self.severity.value,
                "data": self.data, "remediation": self.remediation, "host": self.host}


@dataclass
class ModuleResult:
    module: str
    target: str
    active: bool = False
    phase: int = 1
    ok: bool = True
    skipped: bool = False
    skip_reason: str = ""
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def finish(self) -> "ModuleResult":
        self.finished_at = time.time()
        return self

    @property
    def duration(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def to_dict(self) -> Dict[str, Any]:
        return {"module": self.module, "target": self.target, "active": self.active, "phase": self.phase,
                "ok": self.ok, "skipped": self.skipped, "skip_reason": self.skip_reason,
                "error": self.error, "duration": round(self.duration, 3),
                "findings": [f.to_dict() for f in self.findings]}


@dataclass
class ScanReport:
    target: str
    scan_id: str
    kind: str = "domain"
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    egress: Dict[str, Any] = field(default_factory=dict)
    scope: str = ""
    options: Dict[str, Any] = field(default_factory=dict)
    assets: Dict[str, Any] = field(default_factory=dict)
    modules: List[ModuleResult] = field(default_factory=list)

    def finish(self) -> "ScanReport":
        self.finished_at = time.time()
        return self

    @property
    def finding_count(self) -> int:
        return sum(len(m.findings) for m in self.modules)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for m in self.modules:
            for f in m.findings:
                counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        from .. import __version__
        return {"version": __version__, "target": self.target, "kind": self.kind, "scan_id": self.scan_id,
                "started_at": self.started_at, "finished_at": self.finished_at,
                "duration": round((self.finished_at or time.time()) - self.started_at, 3),
                "egress": self.egress, "scope": self.scope, "options": self.options,
                "assets": self.assets, "finding_count": self.finding_count,
                "severity_counts": self.severity_counts(),
                "modules": [m.to_dict() for m in sorted(self.modules, key=lambda m: (m.phase, m.module))]}
