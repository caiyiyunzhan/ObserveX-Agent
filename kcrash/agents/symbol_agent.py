from __future__ import annotations

from typing import Any

from kcrash.agents.base_agent import Argument, BaseAgent


class SymbolAgent(BaseAgent):
    name = "SymbolAgent"

    def initial_argument(self, context: dict[str, Any]) -> Argument:
        panic_point = context.get("panic_point", "unknown")
        error_class = context.get("error_class", "unknown")
        evidence = context.get("evidence", [])
        confidence = context.get("confidence", 0.5)

        claim = (
            f"Root cause is a symbol-level issue at {panic_point}: "
            f"{error_class}"
        )

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=confidence,
            evidences=list(evidence) if evidence else [
                f"Panic at {panic_point}",
                f"Error class: {error_class}",
            ],
        )

    def rebut(
        self, opponent_arguments: list[Argument], context: dict[str, Any]
    ) -> Argument:
        my_claim = context.get("panic_point", "unknown")
        error_class = context.get("error_class", "unknown")

        challenge_points: list[str] = []
        for arg in opponent_arguments:
            if arg.agent_name == self.name:
                continue

            if arg.confidence > 0.7:
                challenge_points.append(
                    f"{arg.agent_name} proposes '{arg.claim}' "
                    f"with confidence {arg.confidence:.2f}"
                )
            else:
                challenge_points.append(
                    f"{arg.agent_name}'s argument has low confidence "
                    f"({arg.confidence:.2f}), insufficient evidence"
                )

        if challenge_points:
            adjusted_conf = context.get("confidence", 0.5) * 0.9
            claim = (
                f"Symbol analysis still points to {my_claim} ({error_class}), "
                f"but acknowledge alternative hypotheses"
            )
        else:
            adjusted_conf = context.get("confidence", 0.5)
            claim = (
                f"Reaffirm: root cause is at {my_claim} ({error_class}), "
                f"no competing evidence presented"
            )

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=adjusted_conf,
            evidences=[
                f"Panic point: {my_claim}",
                f"Error class: {error_class}",
                *challenge_points,
            ],
        )
