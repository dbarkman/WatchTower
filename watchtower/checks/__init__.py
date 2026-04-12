"""
Health Check Modules
====================
Each module exports a run(config) -> list[CheckResult] function.
"""
from dataclasses import dataclass, field

OK = "ok"
WARNING = "warning"
CRITICAL = "critical"


@dataclass
class CheckResult:
    name: str
    status: str  # ok, warning, critical
    summary: str
    details: str | None = None

    @property
    def icon(self) -> str:
        return {"ok": "\u2705", "warning": "\u26a0\ufe0f", "critical": "\U0001f534"}[self.status]
