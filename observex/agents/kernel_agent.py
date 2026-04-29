from __future__ import annotations

from typing import Any

from observex.agents.base import BaseAgent
from observex.models.debate import (
    AgentRole, DebateArgument, DebatePhase, Evidence,
)
from observex.models.causal import CausalGraph, NodeType


class KernelAgent(BaseAgent):
    role = AgentRole.KERNEL

    def analyze(self, graph: CausalGraph, context: dict[str, Any]) -> DebateArgument:
        kernel_events = [
            n for n in graph.nodes.values()
            if n.source and "kernel" in n.source.lower()
        ]
        ebpf_events = [
            n for n in graph.nodes.values()
            if n.source and "ebpf" in n.source.lower()
        ]

        evidences: list[Evidence] = []
        panic_nodes = [n for n in kernel_events if any(
            k in n.description.lower() for k in ("panic", "oops", "bug", "fault", "segv")
        )]
        lockup_nodes = [n for n in kernel_events if any(
            k in n.description.lower() for k in ("softlockup", "hardlockup", "hung", "stall")
        )]
        oom_nodes = [n for n in kernel_events if any(
            k in n.description.lower() for k in ("oom", "out of memory", "memory cgroup")
        )]

        if panic_nodes:
            best = panic_nodes[0]
            claim = f"Kernel panic detected: {best.label[:120]}"
            confidence = 0.85
            evidences = [
                Evidence(source_system="kernel", content=n.description[:200], timestamp=n.timestamp)
                for n in panic_nodes[:5]
            ]
        elif lockup_nodes:
            best = lockup_nodes[0]
            claim = f"CPU/IO lockup detected: {best.label[:120]}"
            confidence = 0.75
            evidences = [
                Evidence(source_system="kernel", content=n.description[:200], timestamp=n.timestamp)
                for n in lockup_nodes[:5]
            ]
        elif oom_nodes:
            claim = f"OOM condition in kernel: {oom_nodes[0].label[:120]}"
            confidence = 0.8
            evidences = [
                Evidence(source_system="kernel", content=n.description[:200])
                for n in oom_nodes[:5]
            ]
        elif ebpf_events:
            claim = f"eBPF probes detected anomalies: {len(ebpf_events)} events"
            confidence = 0.6
            evidences = [
                Evidence(source_system="ebpf", content=n.description[:200])
                for n in ebpf_events[:5]
            ]
        elif kernel_events:
            claim = f"Kernel subsystem events: {len(kernel_events)} related events observed"
            confidence = 0.4
            evidences = [
                Evidence(source_system="kernel", content=n.description[:200])
                for n in kernel_events[:5]
            ]
        else:
            claim = "No kernel-level anomalies detected"
            confidence = 0.1

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.INITIAL,
            claim=claim,
            confidence=confidence,
            evidences=evidences,
        )

    def rebut(
        self,
        opponents: list[DebateArgument],
        graph: CausalGraph,
        context: dict[str, Any],
    ) -> DebateArgument:
        kernel_events = [n for n in graph.nodes.values() if n.source and "kernel" in n.source.lower()]
        has_kernel_issue = len(kernel_events) > 0

        challenges: list[str] = []
        support: list[str] = []

        for arg in opponents:
            if arg.agent_role == self.role:
                continue
            if "application" in arg.claim.lower() and has_kernel_issue:
                challenges.append(
                    f"ApplicationAgent attributes fault to app, but {len(kernel_events)} kernel events "
                    f"suggest the kernel is the origin — apps can't cause kernel panics"
                )
            elif "infra" in arg.claim.lower() and has_kernel_issue:
                support.append(
                    f"InfrastructureAgent may be correct — hardware issues can trigger kernel events"
                )

        if challenges:
            adjusted = context.get("kernel_confidence", 0.6) * 1.1
            claim = f"Kernel root cause reaffirmed with cross-source validation"
        else:
            adjusted = context.get("kernel_confidence", 0.3) * 0.9
            claim = "Kernel evidence is weak; other sources may be primary"

        return DebateArgument(
            agent_role=self.role,
            phase=DebatePhase.REBUTTAL,
            claim=claim,
            confidence=min(adjusted, 1.0),
            evidences=[
                Evidence(source_system="kernel", content=c) for c in challenges + support
            ],
        )
