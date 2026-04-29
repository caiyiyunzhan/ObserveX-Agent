from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from kcrash.collector.vmcore_reader import Frame
from kcrash.core.fingerprint import CrashFingerprint
from kcrash.core.severity import Severity, SeverityAssessment


@dataclass
class AnalysisReport:
    vmcore_path: str
    vmlinux_path: str
    hostname: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    frames: list[Frame] = field(default_factory=list)
    dmesg: str = ""
    mock_data: dict[str, Any] | None = None

    fingerprint: CrashFingerprint | None = None
    severity: SeverityAssessment | None = None

    phase1_result: dict[str, Any] = field(default_factory=dict)
    phase2_result: dict[str, Any] = field(default_factory=dict)
    debate_result: dict[str, Any] = field(default_factory=dict)

    root_cause: str = ""
    confidence: float = 0.0
    verdict_agent: str = ""
    transcript: str = ""

    patch_type: str = ""
    patch_code: str = ""
    patch_valid: bool = False
    patch_validation_msg: str = ""

    total_duration_ms: float = 0.0
    token_usage: dict[str, int] = field(default_factory=dict)
    pipeline_stages: list[dict[str, Any]] = field(default_factory=list)

    status: str = "completed"
    error: str = ""

    def set_failed(self, error: str) -> None:
        self.status = "failed"
        self.error = error

    def merge_cached(self, cached: dict[str, Any]) -> None:
        self.root_cause = cached.get("root_cause", "")
        self.confidence = cached.get("confidence", 0.0)
        self.transcript = cached.get("transcript", "")
        self.patch_code = cached.get("patch_code", "")
        self.status = "cached"

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "vmcore_path": self.vmcore_path,
        }

        if self.fingerprint:
            result["fingerprint"] = self.fingerprint.to_dict()

        if self.severity:
            result["severity"] = {
                "level": self.severity.level.label(),
                "score": self.severity.score,
                "factors": self.severity.factors,
                "sla_impact": self.severity.sla_impact,
                "recommended_action": self.severity.recommended_action,
            }

        result["root_cause"] = self.root_cause
        result["confidence"] = self.confidence
        result["verdict_agent"] = self.verdict_agent

        if self.debate_result:
            result["is_consensus"] = self.debate_result.get("is_consensus", False)
            result["round_details"] = self.debate_result.get("round_details", [])

        if self.patch_code:
            result["patch"] = {
                "type": self.patch_type,
                "code": self.patch_code,
                "valid": self.patch_valid,
                "validation_msg": self.patch_validation_msg,
            }

        result["transcript"] = self.transcript
        result["total_duration_ms"] = self.total_duration_ms
        result["token_usage"] = self.token_usage
        result["pipeline_stages"] = self.pipeline_stages

        if self.error:
            result["error"] = self.error

        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, default=str)

    def summary(self) -> str:
        lines = [
            f"[{'CRITICAL' if self.severity and self.severity.level.value >= 4 else 'ANALYSIS'}] "
            f"Fingerprint: {self.fingerprint.hash_value if self.fingerprint else 'N/A'}",
            f"  Root cause: {self.root_cause or 'Not determined'}",
            f"  Confidence: {self.confidence:.2f}",
            f"  Verdict by: {self.verdict_agent}",
        ]
        if self.severity:
            lines.append(
                f"  Severity: {self.severity.level.label()} ({self.severity.score:.0f}/100)"
            )
            lines.append(f"  Action: {self.severity.recommended_action}")
        if self.patch_code:
            lines.append(f"  Patch type: {self.patch_type} (valid={self.patch_valid})")
        lines.append(f"  Duration: {self.total_duration_ms:.0f}ms")
        lines.append(f"  Tokens: {self.token_usage.get('total_tokens', 0)}")
        return "\n".join(lines)
