from __future__ import annotations

from typing import Any

from observex.agents.base import BaseAgent
from observex.models.debate import AgentRole, DebateArgument, DebatePhase, Evidence
from observex.models.causal import CausalGraph, NodeType


class ApplicationAgent(BaseAgent):
    role = AgentRole.APPLICATION

    def analyze(self, graph: CausalGraph, context: dict[str, Any]) -> DebateArgument:
        app_events = [
            n for n in graph.nodes.values()
            if n.source and any(s in n.source.lower() for s in ("application", "container", "app"))
        ]

        error_events = [n for n in app_events if n.severity in ("error", "critical", "fatal")]
        timeout_events = [n for n in app_events if "timeout" in n.description.lower()]
        oom_app = [n for n in app_events if any(
            k in n.description.lower() for k in ("heap", "gc", "outofmemory", "memory limit")
        )]
        connection_events = [n for n in app_events if any(
            k in n.description.lower() for k in ("connection pool", "refused", "reset", "broken pipe")
        )]

        evidences: list[Evidence] = []

        if oom_app:
            claim = f"Application OOM/GC pressure: {oom_app[0].label[:120]}"
            confidence = 0.8
            evidences = [Evidence(source_system="app", content=n.description[:200]) for n in oom_app[:5]]
        elif timeout_events:
            claim = f"Application timeouts detected: {len(timeout_events)} timeout events"
            confidence = 0.7
            evidences = [Evidence(source_system="app", content=n.description[:200]) for n in timeout_events[:5]]
        elif connection_events:
            claim = f"Connection pool exhaustion: {connection_events[0].label[:120]}"
            confidence = 0.75
            evidences = [Evidence(source_system="app", content=n.description[:200]) for n in connection_events[:5]]
        elif error_events:
            claim = f"Application errors: {len(error_events)} error-level events"
            confidence = 0.5
            evidences = [Evidence(source_system="app", content=n.description[:200]) for n in error_events[:5]]
        elif app_events:
            claim = f"Application events: {len(app_events)} events observed"
            confidence = 0.3
            evidences = [Evidence(source_system="app", content=n.description[:200]) for n in app_events[:3]]
        else:
            claim = "No application-level anomalies detected"
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
        app_events = [n for n in graph.nodes.values() if n.source and "app" in n.source.lower()]

        challenges: list[str] = []
        for arg in opponents:
            if arg.agent_role == self.role:
                continue
            if "kernel" in arg.claim.lower() and any("timeout" in n.description.lower() for n in app_events):
                challenges.append(
                    "Kernel events are downstream — application timeouts preceded kernel subsystem issues, "
                    "suggesting app-level memory/GC pressure is the root cause"
                )

        if challenges:
            adjusted = context.get("app_confidence", 0.6) * 1.05
            claim = "Application root cause validated against kernel timeline"
        else:
            adjusted = context.get("app_confidence", 0.4) * 0.85
            claim = "Application evidence insufficient to claim root cause"

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.REBUTTAL,
            claim=claim,
            confidence=min(adjusted, 1.0),
            evidences=[Evidence(source_system="app", content=c) for c in challenges],
        )
