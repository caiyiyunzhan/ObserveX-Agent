from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RemediationType(str, Enum):
    KERNEL_PARAM = "kernel_param"
    SERVICE_RESTART = "service_restart"
    EBP_PATCH = "ebpf_patch"
    CONFIG_CHANGE = "config_change"
    JIRA_TICKET = "jira_ticket"
    ROLLBACK = "rollback"
    SCALE_UP = "scale_up"
    NETWORK_ACL = "network_acl"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RemediationStep:
    step_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    step_type: RemediationType = RemediationType.KERNEL_PARAM
    description: str = ""
    command: str = ""
    target_host: str = ""
    target_service: str = ""
    code: str = ""
    rollback_command: str = ""
    estimated_risk: float = 0.0
    requires_approval: bool = False


@dataclass
class SandboxResult:
    sandbox_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    status: VerificationStatus = VerificationStatus.PENDING
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: float = 0.0
    error_message: str = ""
    iteration: int = 0


@dataclass
class RemediationPlan:
    plan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str = ""
    root_cause: str = ""
    confidence: float = 0.0
    steps: list[RemediationStep] = field(default_factory=list)
    sandbox_results: list[SandboxResult] = field(default_factory=list)
    iterations: int = 0
    max_iterations: int = 5
    total_tokens: int = 0
    status: str = "pending"

    def add_step(self, step: RemediationStep) -> None:
        self.steps.append(step)

    def add_sandbox_result(self, result: SandboxResult) -> None:
        self.sandbox_results.append(result)
        self.iterations += 1

    @property
    def can_retry(self) -> bool:
        return self.iterations < self.max_iterations

    @property
    def latest_result(self) -> SandboxResult | None:
        return self.sandbox_results[-1] if self.sandbox_results else None

    @property
    def is_verified(self) -> bool:
        return (
            self.latest_result is not None
            and self.latest_result.status == VerificationStatus.PASSED
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "incident_id": self.incident_id,
            "root_cause": self.root_cause,
            "confidence": self.confidence,
            "step_count": len(self.steps),
            "iterations": self.iterations,
            "verified": self.is_verified,
            "total_tokens": self.total_tokens,
            "steps": [
                {
                    "type": s.step_type.value,
                    "description": s.description,
                    "command": s.command,
                    "risk": s.estimated_risk,
                    "requires_approval": s.requires_approval,
                }
                for s in self.steps
            ],
        }
