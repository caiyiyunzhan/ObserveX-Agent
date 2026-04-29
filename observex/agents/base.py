from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from observex.models.debate import (
    AgentRole, DebateArgument, DebatePhase, Evidence, DebateSession,
)
from observex.models.causal import CausalGraph


class BaseAgent(ABC):
    role: AgentRole

    @abstractmethod
    def analyze(self, graph: CausalGraph, context: dict[str, Any]) -> DebateArgument:
        raise NotImplementedError

    @abstractmethod
    def rebut(
        self,
        opponents: list[DebateArgument],
        graph: CausalGraph,
        context: dict[str, Any],
    ) -> DebateArgument:
        raise NotImplementedError

    def _collect_evidence(
        self, source: str, items: list[dict[str, Any]]
    ) -> list[Evidence]:
        return [
            Evidence(
                source_system=source,
                timestamp=item.get("timestamp", 0),
                content=item.get("content", str(item)),
                metric_name=item.get("metric", ""),
                metric_value=item.get("value", 0),
            )
            for item in items
        ]
