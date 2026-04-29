from __future__ import annotations

import time
from typing import Any

from observex.models.debate import (
    AgentRole, DebateArgument, DebatePhase, DebateSession, Evidence,
)
from observex.models.causal import CausalGraph
from observex.agents.base import BaseAgent
from observex.agents.kernel_agent import KernelAgent
from observex.agents.application_agent import ApplicationAgent
from observex.agents.infra_agent import InfrastructureAgent
from observex.agents.change_agent import ChangeAgent


class DebateEngine:
    def __init__(self, rounds: int = 2, min_confidence: float = 0.6) -> None:
        self._rounds = rounds
        self._min_confidence = min_confidence
        self._agents: dict[AgentRole, BaseAgent] = {
            AgentRole.KERNEL: KernelAgent(),
            AgentRole.APPLICATION: ApplicationAgent(),
            AgentRole.INFRASTRUCTURE: InfrastructureAgent(),
            AgentRole.CHANGE: ChangeAgent(),
        }

    def run(
        self,
        graph: CausalGraph,
        incident_id: str = "",
        hypothesis: str = "",
        context: dict[str, Any] | None = None,
    ) -> DebateSession:
        ctx = context or {}
        session = DebateSession(
            incident_id=incident_id,
            causal_hypothesis=hypothesis,
            rounds=self._rounds,
        )

        for role, agent in self._agents.items():
            arg = agent.analyze(graph, ctx)
            session.add_argument(arg)

        for round_num in range(2, self._rounds + 1):
            for role, agent in self._agents.items():
                opponents = session.get_round_arguments(
                    DebatePhase.INITIAL if round_num == 2 else DebatePhase.REBUTTAL,
                    exclude_role=role,
                )
                arg = agent.rebut(opponents, graph, ctx)
                session.add_argument(arg)

        self._resolve_verdict(session)

        return session

    def _resolve_verdict(self, session: DebateSession) -> None:
        final_args: dict[AgentRole, DebateArgument] = {}
        for arg in session.arguments:
            if arg.phase == DebatePhase.REBUTTAL:
                final_args[arg.agent_role] = arg
            elif arg.agent_role not in final_args:
                final_args[arg.agent_role] = arg

        if not final_args:
            session.verdict = "Insufficient data for diagnosis"
            session.verdict_confidence = 0.0
            return

        best_role = max(final_args, key=lambda r: final_args[r].confidence)
        best_arg = final_args[best_role]

        confidences = [a.confidence for a in final_args.values()]
        avg_conf = sum(confidences) / len(confidences) if confidences else 0

        top_count = sum(1 for a in final_args.values() if a.confidence == best_arg.confidence)
        is_consensus = top_count == 1 and best_arg.confidence > avg_conf * 1.3

        if not is_consensus:
            adjusted = best_arg.confidence * 0.85
        else:
            adjusted = best_arg.confidence

        session.verdict = f"[{best_role.value}] {best_arg.claim}"
        session.verdict_confidence = adjusted
        session.is_consensus = is_consensus
