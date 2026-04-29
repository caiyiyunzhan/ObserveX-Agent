from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kcrash.agents.base_agent import Argument


@dataclass
class DebateEntry:
    round_number: int
    phase: str
    agent_name: str
    argument: Argument


class DebateMemory:
    def __init__(self) -> None:
        self._entries: list[DebateEntry] = []

    def record(
        self,
        round_number: int,
        phase: str,
        agent_name: str,
        argument: Argument,
    ) -> None:
        entry = DebateEntry(
            round_number=round_number,
            phase=phase,
            agent_name=agent_name,
            argument=argument,
        )
        self._entries.append(entry)

    def get_agent_arguments(
        self, agent_name: str, exclude_round: int | None = None
    ) -> list[Argument]:
        return [
            e.argument
            for e in self._entries
            if e.agent_name == agent_name
            and (exclude_round is None or e.round_number != exclude_round)
        ]

    def get_round_arguments(
        self, round_number: int, exclude_agent: str | None = None
    ) -> list[Argument]:
        return [
            e.argument
            for e in self._entries
            if e.round_number == round_number
            and (exclude_agent is None or e.agent_name != exclude_agent)
        ]

    def get_opponent_arguments(
        self, agent_name: str, round_number: int
    ) -> list[Argument]:
        return [
            e.argument
            for e in self._entries
            if e.round_number == round_number
            and e.agent_name != agent_name
        ]

    def transcript(self) -> str:
        lines: list[str] = []
        current_round = -1

        for entry in self._entries:
            if entry.round_number != current_round:
                current_round = entry.round_number
                lines.append(f"\n{'='*60}")
                lines.append(f"Round {current_round} - {entry.phase}")
                lines.append(f"{'='*60}")

            arg = entry.argument
            lines.append(f"\n[{arg.agent_name}]")
            lines.append(f"  Claim: {arg.claim}")
            lines.append(f"  Confidence: {arg.confidence:.2f}")
            lines.append(f"  Evidence:")
            for ev in arg.evidences:
                lines.append(f"    - {ev}")

        return "\n".join(lines)

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "round": e.round_number,
                "phase": e.phase,
                "agent": e.agent_name,
                "claim": e.argument.claim,
                "confidence": e.argument.confidence,
                "evidences": e.argument.evidences,
            }
            for e in self._entries
        ]
