from __future__ import annotations

from typing import Any

from observex.agents.base import BaseAgent
from observex.models.debate import AgentRole, DebateArgument, DebatePhase, Evidence
from observex.models.causal import CausalGraph, NodeType


class ChangeAgent(BaseAgent):
    role = AgentRole.CHANGE

    def analyze(self, graph: CausalGraph, context: dict[str, Any]) -> DebateArgument:
        change_nodes = [
            n for n in graph.nodes.values()
            if n.node_type == NodeType.CHANGE
        ]

        recent_changes = sorted(change_nodes, key=lambda n: n.timestamp, reverse=True)

        evidences: list[Evidence] = []

        if recent_changes:
            top = recent_changes[0]
            claim = f"Recent change detected: {top.label[:120]}"
            confidence = 0.7

            for node in recent_changes[:5]:
                evidences.append(Evidence(
                    source_system="cmdb",
                    content=node.description[:200],
                    timestamp=node.timestamp,
                ))

            has_rollback = any("rollback" in n.description.lower() for n in recent_changes)
            if has_rollback:
                claim += " (rollback in progress)"
                confidence += 0.1

            has_kernel_change = any(
                "kernel" in n.description.lower() or "driver" in n.description.lower()
                for n in recent_changes
            )
            if has_kernel_change:
                confidence += 0.15
                claim = f"Kernel/driver change detected: {top.label[:120]}"

        else:
            claim = "No recent changes found in CMDB/工单 system"
            confidence = 0.1

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.INITIAL,
            claim=claim,
            confidence=min(confidence, 1.0),
            evidences=evidences,
        )

    def rebut(
        self, opponents: list[DebateArgument], graph: CausalGraph, context: dict[str, Any]
    ) -> DebateArgument:
        change_nodes = [n for n in graph.nodes.values() if n.node_type == NodeType.CHANGE]

        challenges: list[str] = []
        for arg in opponents:
            if arg.agent_role == self.role:
                continue
            if arg.confidence > 0.7 and change_nodes:
                challenges.append(
                    f"{arg.agent_role.value}Agent has strong evidence (conf={arg.confidence:.2f}), "
                    f"but {len(change_nodes)} recent changes are a high-probability cause — "
                    f"regressions from deployments are statistically the #1 source of outages"
                )

        if challenges and change_nodes:
            adjusted = 0.65
            claim = "Change-based root cause remains primary hypothesis"
        elif change_nodes:
            adjusted = 0.5
            claim = "Changes present but evidence is circumstantial"
        else:
            adjusted = 0.15
            claim = "No change data available to support this hypothesis"

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.REBUTTAL,
            claim=claim,
            confidence=adjusted,
            evidences=[Evidence(source_system="cmdb", content=c) for c in challenges],
        )
