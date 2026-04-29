from __future__ import annotations

from typing import Any

from kcrash.agents.base_agent import Argument, BaseAgent
from kcrash.debate.memory import DebateMemory


class DebateModerator:
    def __init__(self, agents: list[BaseAgent], rounds: int = 2) -> None:
        self.agents = agents
        self.rounds = rounds
        self.memory = DebateMemory()

    def conduct(self, context: dict[str, Any]) -> dict[str, Any]:
        for round_num in range(1, self.rounds + 1):
            if round_num == 1:
                self._run_initial_round(context)
            else:
                self._run_rebut_round(round_num, context)

        return self._resolve_verdict()

    def _run_initial_round(self, context: dict[str, Any]) -> None:
        print(f"\n--- Debate Round 1: Initial Arguments ---")
        for agent in self.agents:
            argument = agent.initial_argument(context)
            self.memory.record(
                round_number=1,
                phase="initial",
                agent_name=agent.name,
                argument=argument,
            )
            print(
                f"  [{agent.name}] confidence={argument.confidence:.2f}: "
                f"{argument.claim}"
            )

    def _run_rebut_round(
        self, round_num: int, context: dict[str, Any]
    ) -> None:
        print(f"\n--- Debate Round {round_num}: Rebuttals ---")
        for agent in self.agents:
            opponents = self.memory.get_opponent_arguments(
                agent_name=agent.name, round_number=round_num - 1
            )
            argument = agent.rebut(opponents, context)
            self.memory.record(
                round_number=round_num,
                phase="rebut",
                agent_name=agent.name,
                argument=argument,
            )
            print(
                f"  [{agent.name}] confidence={argument.confidence:.2f}: "
                f"{argument.claim}"
            )

    def _resolve_verdict(self) -> dict[str, Any]:
        all_arguments: dict[str, list[Argument]] = {}
        for agent in self.agents:
            all_arguments[agent.name] = self.memory.get_agent_arguments(
                agent.name
            )

        final_arguments: list[Argument] = []
        for agent_name, args in all_arguments.items():
            if args:
                final_arguments.append(args[-1])

        max_arg = max(final_arguments, key=lambda a: a.confidence)

        confidences = [a.confidence for a in final_arguments]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        top_count = sum(
            1 for a in final_arguments if a.confidence == max_arg.confidence
        )
        is_consensus = top_count == 1 and max_arg.confidence > avg_confidence * 1.2

        if not is_consensus and len(final_arguments) > 1:
            final_confidence = max_arg.confidence * 0.85
        else:
            final_confidence = max_arg.confidence

        verdict = Argument(
            agent_name=max_arg.agent_name,
            claim=max_arg.claim,
            confidence=final_confidence,
            evidences=max_arg.evidences,
        )

        transcript = self.memory.transcript()

        print(f"\n--- Verdict ---")
        print(f"  Agent: {verdict.agent_name}")
        print(f"  Claim: {verdict.claim}")
        print(f"  Confidence: {verdict.confidence:.2f}")
        print(f"  Consensus: {is_consensus}")

        return {
            "verdict": verdict,
            "final_confidence": final_confidence,
            "is_consensus": is_consensus,
            "transcript": transcript,
            "round_details": self.memory.to_dict(),
        }
