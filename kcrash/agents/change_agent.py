from __future__ import annotations

from typing import Any

from kcrash.agents.base_agent import Argument, BaseAgent


class ChangeAgent(BaseAgent):
    name = "ChangeAgent"

    def initial_argument(self, context: dict[str, Any]) -> Argument:
        candidates = context.get("root_cause_candidates", [])
        changes = context.get("_collected_changes", [])

        if not candidates:
            return Argument(
                agent_name=self.name,
                claim="Insufficient change data to form hypothesis",
                confidence=0.1,
                evidences=["No root cause candidates from change correlation"],
            )

        top = max(candidates, key=lambda c: c.get("probability", 0))
        claim = f"Root cause likely from recent change: {top['claim']}"

        evidences = [
            f"Probability: {top.get('probability', 0):.2f}",
            *top.get("evidence_chain", []),
        ]

        if changes:
            for c in changes[:3]:
                evidences.append(
                    f"Recent change: {c['type']} {c['name']} "
                    f"{c['old']} -> {c['new']}"
                )

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=top.get("probability", 0.3),
            evidences=evidences,
        )

    def rebut(
        self, opponent_arguments: list[Argument], context: dict[str, Any]
    ) -> Argument:
        candidates = context.get("root_cause_candidates", [])
        changes = context.get("_collected_changes", [])

        if not candidates:
            return Argument(
                agent_name=self.name,
                claim="Cannot identify a change-based root cause",
                confidence=0.1,
                evidences=["No candidates available"],
            )

        top = max(candidates, key=lambda c: c.get("probability", 0))

        supporting_points: list[str] = []
        contradicting_points: list[str] = []

        for arg in opponent_arguments:
            if arg.agent_name == self.name:
                continue

            if "hardware" in arg.claim.lower():
                contradicting_points.append(
                    f"{arg.agent_name} suggests hardware cause, "
                    f"but recent kernel changes are a more common source of regressions"
                )
            elif arg.confidence > top.get("probability", 0):
                supporting_points.append(
                    f"{arg.agent_name}'s argument ({arg.confidence:.2f}) "
                    f"is stronger, may be co-contributor"
                )

        all_evidences = [
            f"Primary candidate: {top['claim']} "
            f"(p={top.get('probability', 0):.2f})",
            *top.get("evidence_chain", []),
            *supporting_points,
            *contradicting_points,
        ]

        adjusted_conf = top.get("probability", 0.3)
        if contradicting_points:
            adjusted_conf *= 0.85

        claim = (
            f"Maintain change-based root cause: {top['claim']}"
            if not contradicting_points
            else f"Change-based root cause ({top['claim']}) with "
            f"possible hardware interaction"
        )

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=adjusted_conf,
            evidences=all_evidences,
        )
