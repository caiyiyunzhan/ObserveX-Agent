from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from kcrash.collector.vmcore_reader import Frame
from kcrash.core.fingerprint import CrashFingerprint


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}[self.value]


@dataclass
class SeverityAssessment:
    level: Severity
    score: float
    factors: list[str]
    sla_impact: str
    recommended_action: str


ERROR_SEVERITY_MAP = {
    "kernel_panic": 4,
    "double_fault": 4,
    "nmi": 4,
    "kernel_bug": 3,
    "kernel_oops": 3,
    "gpf": 3,
    "null_deref": 3,
    "page_fault": 2,
    "divide_error": 2,
    "stack_overflow": 3,
    "unknown": 1,
}

PANIC_MODULES = {"mlx5_core", "nvme", "dm_multipath", "iscsi", "btrfs", "xfs"}


def assess_severity(
    fingerprint: CrashFingerprint,
    frames: list[Frame],
    hw_errors: list[dict] | None = None,
    sibling_crash_count: int = 0,
) -> SeverityAssessment:
    factors: list[str] = []
    score = 0.0

    error_base = ERROR_SEVERITY_MAP.get(fingerprint.error_class, 1)
    score += error_base * 15
    factors.append(f"Error class: {fingerprint.error_class} (base={error_base})")

    if fingerprint.module in PANIC_MODULES:
        score += 20
        factors.append(f"Critical subsystem: {fingerprint.module}")

    if fingerprint.depth > 10:
        score += 10
        factors.append(f"Deep stack ({fingerprint.depth} frames), possible recursion")

    if hw_errors:
        critical_hw = sum(
            1 for e in hw_errors if e.get("severity") == "critical"
        )
        if critical_hw > 0:
            score += critical_hw * 15
            factors.append(f"{critical_hw} critical hardware error(s)")

    if sibling_crash_count > 0:
        penalty = min(sibling_crash_count * 5, 25)
        score += penalty
        factors.append(
            f"{sibling_crash_count} sibling crash(es) detected (cluster-wide issue)"
        )

    score = min(score, 100.0)

    if score >= 80:
        level = Severity.CRITICAL
        sla = "Service outage likely, immediate response required"
        action = "Page on-call SRE, auto-generate hot-patch if possible"
    elif score >= 60:
        level = Severity.HIGH
        sla = "Performance degradation or partial outage"
        action = "Notify SRE team, investigate within 30 minutes"
    elif score >= 35:
        level = Severity.MEDIUM
        sla = "Potential impact, monitoring recommended"
        action = "Create ticket, investigate within 4 hours"
    else:
        level = Severity.LOW
        sla = "Minimal immediate impact"
        action = "Log for trend analysis, investigate during next sprint"

    return SeverityAssessment(
        level=level,
        score=score,
        factors=factors,
        sla_impact=sla,
        recommended_action=action,
    )
