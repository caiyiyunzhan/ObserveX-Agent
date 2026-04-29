from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentRole(str, Enum):
    KERNEL = "kernel"
    APPLICATION = "application"
    INFRASTRUCTURE = "infrastructure"
    CHANGE = "change"


class DebatePhase(str, Enum):
    INITIAL = "initial"
    REBUTTAL = "rebuttal"
    CONSENSUS = "consensus"


@dataclass
class Evidence:
    evidence_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    source_system: str = ""
    timestamp: float = 0.0
    content: str = ""
    metric_name: str = ""
    metric_value: float = 0.0
    raw_data: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_system,
            "timestamp": self.timestamp,
            "content": self.content,
        }


@dataclass
class DebateArgument:
    argument_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    agent_role: AgentRole = AgentRole.KERNEL
    phase: DebatePhase = DebatePhase.INITIAL
    claim: str = ""
    confidence: float = 0.0
    evidences: list[Evidence] = field(default_factory=list)
    rebut_target: str = ""
    timestamp: float = 0.0
    token_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_role.value,
            "phase": self.phase.value,
            "claim": self.claim,
            "confidence": self.confidence,
            "evidence_count": len(self.evidences),
            "evidences": [e.to_dict() for e in self.evidences],
        }


@dataclass
class DebateSession:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str = ""
    causal_hypothesis: str = ""
    agents: list[AgentRole] = field(
        default_factory=lambda: list(AgentRole)
    )
    rounds: int = 2
    arguments: list[DebateArgument] = field(default_factory=list)
    verdict: str = ""
    verdict_confidence: float = 0.0
    is_consensus: bool = False
    total_tokens: int = 0

    def add_argument(self, arg: DebateArgument) -> None:
        self.arguments.append(arg)
        self.total_tokens += arg.token_count

    def get_agent_arguments(
        self, role: AgentRole, exclude_phase: DebatePhase | None = None
    ) -> list[DebateArgument]:
        return [
            a for a in self.arguments
            if a.agent_role == role
            and (exclude_phase is None or a.phase != exclude_phase)
        ]

    def get_round_arguments(
        self, round_phase: DebatePhase, exclude_role: AgentRole | None = None
    ) -> list[DebateArgument]:
        return [
            a for a in self.arguments
            if a.phase == round_phase
            and (exclude_role is None or a.agent_role != exclude_role)
        ]

    def transcript(self) -> str:
        lines: list[str] = [
            f"=== Debate Session {self.session_id} ===",
            f"Hypothesis: {self.causal_hypothesis}",
            "",
        ]
        current_phase = None
        for arg in self.arguments:
            if arg.phase != current_phase:
                current_phase = arg.phase
                lines.append(f"--- {current_phase.value.upper()} ---")
            lines.append(f"[{arg.agent_role.value}] (conf={arg.confidence:.2f})")
            lines.append(f"  {arg.claim}")
            for ev in arg.evidences[:3]:
                lines.append(f"    | {ev.source_system}: {ev.content[:100]}")
            lines.append("")

        lines.append(f"=== VERDICT ===")
        lines.append(f"  {self.verdict}")
        lines.append(f"  Confidence: {self.verdict_confidence:.2f}")
        lines.append(f"  Consensus: {self.is_consensus}")
        lines.append(f"  Total tokens: {self.total_tokens}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "incident_id": self.incident_id,
            "hypothesis": self.causal_hypothesis,
            "rounds": self.rounds,
            "argument_count": len(self.arguments),
            "verdict": self.verdict,
            "confidence": self.verdict_confidence,
            "consensus": self.is_consensus,
            "total_tokens": self.total_tokens,
            "arguments": [a.to_dict() for a in self.arguments],
        }
