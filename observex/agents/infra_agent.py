from __future__ import annotations

from typing import Any

from observex.agents.base import BaseAgent
from observex.models.debate import AgentRole, DebateArgument, DebatePhase, Evidence
from observex.models.causal import CausalGraph, NodeType


class InfrastructureAgent(BaseAgent):
    role = AgentRole.INFRASTRUCTURE

    def analyze(self, graph: CausalGraph, context: dict[str, Any]) -> DebateArgument:
        infra_events = [
            n for n in graph.nodes.values()
            if n.source and any(s in n.source.lower() for s in ("infra", "network", "storage", "snmp", "power", "temp"))
        ]

        network_issues = [n for n in infra_events if any(
            k in n.description.lower() for k in ("link down", "packet loss", "switch", "port error", "crc")
        )]
        disk_issues = [n for n in infra_events if any(
            k in n.description.lower() for k in ("smart", "disk", "i/o error", "sector", "raid")
        )]
        power_temp = [n for n in infra_events if any(
            k in n.description.lower() for k in ("power", "temperature", "fan", "thermal", "psu")
        )]

        evidences: list[Evidence] = []

        if network_issues:
            claim = f"Network infrastructure failure: {network_issues[0].label[:120]}"
            confidence = 0.85
            evidences = [Evidence(source_system="infra", content=n.description[:200]) for n in network_issues[:5]]
        elif disk_issues:
            claim = f"Storage subsystem failure: {disk_issues[0].label[:120]}"
            confidence = 0.8
            evidences = [Evidence(source_system="infra", content=n.description[:200]) for n in disk_issues[:5]]
        elif power_temp:
            claim = f"Power/thermal anomaly: {power_temp[0].label[:120]}"
            confidence = 0.7
            evidences = [Evidence(source_system="infra", content=n.description[:200]) for n in power_temp[:5]]
        elif infra_events:
            claim = f"Infrastructure events: {len(infra_events)} events observed"
            confidence = 0.3
            evidences = [Evidence(source_system="infra", content=n.description[:200]) for n in infra_events[:3]]
        else:
            claim = "No infrastructure anomalies detected"
            confidence = 0.1

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.INITIAL,
            claim=claim,
            confidence=confidence,
            evidences=evidences,
        )

    def rebut(
        self, opponents: list[DebateArgument], graph: CausalGraph, context: dict[str, Any]
    ) -> DebateArgument:
        infra_events = [n for n in graph.nodes.values() if n.source and "infra" in n.source.lower()]

        challenges: list[str] = []
        for arg in opponents:
            if arg.agent_role == self.role:
                continue
            if "change" in arg.claim.lower() and infra_events:
                challenges.append(
                    "ChangeAgent suggests config change, but infrastructure errors "
                    "existed before the change — likely a pre-existing hardware fault"
                )

        if challenges:
            adjusted = context.get("infra_confidence", 0.5) * 1.1
        else:
            adjusted = context.get("infra_confidence", 0.3) * 0.9

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.REBUTTAL,
            claim=challenges[0] if challenges else "Infrastructure role is secondary in this incident",
            confidence=min(adjusted, 1.0),
            evidences=[Evidence(source_system="infra", content=c) for c in challenges],
        )
