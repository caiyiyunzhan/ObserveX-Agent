from __future__ import annotations

import time
import uuid
from typing import Any

from observex.models.events import RawEvent, ClusteredEvent, ChangeEvent
from observex.models.causal import CausalGraph
from observex.models.debate import DebateSession
from observex.models.remediation import RemediationPlan
from observex.stream.ingestion import EventStreamProcessor
from observex.processing.clustering import EventClusterer, CrossSourceCorrelator
from observex.processing.causal_builder import CausalGraphBuilder
from observex.debate.engine import DebateEngine
from observex.remediation.engine import RemediationEngine
from observex.knowledge.base import KnowledgeBase


class ObserveXPipeline:
    def __init__(
        self,
        debate_rounds: int = 2,
        min_confidence: float = 0.6,
        enable_remediation: bool = True,
        kb_dir: str = ".observex_kb",
        cluster_window: int = 60,
        correlation_window_ms: float = 5000,
    ) -> None:
        self._clusterer = EventClusterer(window_seconds=cluster_window)
        self._correlator = CrossSourceCorrelator(time_window_ms=correlation_window_ms)
        self._debate_engine = DebateEngine(rounds=debate_rounds, min_confidence=min_confidence)
        self._remediation_engine = RemediationEngine()
        self._knowledge_base = KnowledgeBase(kb_dir=kb_dir)
        self._enable_remediation = enable_remediation
        self._min_confidence = min_confidence

    def process_events(
        self,
        events: list[RawEvent],
        changes: list[ChangeEvent] | None = None,
        incident_id: str = "",
    ) -> dict[str, Any]:
        incident_id = incident_id or f"inc-{uuid.uuid4().hex[:8]}"
        start = time.time()

        cluster_result = self._clusterer.ingest_batch(events)
        active_clusters = self._clusterer.get_active_clusters(min_count=1)

        correlations = self._correlator.correlate(active_clusters)

        builder = CausalGraphBuilder(incident_id=incident_id)
        graph = builder.build_from_correlations(active_clusters, changes or [])

        matched_patterns = []
        if graph.nodes:
            sig = [n.label for n in list(graph.nodes.values())[:10]]
            matched_patterns = self._knowledge_base.match_pattern(sig)

        hypothesis = self._form_hypothesis(graph, matched_patterns)

        context = {
            "correlations": correlations,
            "matched_patterns": [p.to_dict() for p in matched_patterns],
            "cluster_stats": cluster_result,
        }

        debate = self._debate_engine.run(
            graph=graph,
            incident_id=incident_id,
            hypothesis=hypothesis,
            context=context,
        )

        plan = None
        if (
            self._enable_remediation
            and debate.verdict_confidence >= self._min_confidence
        ):
            plan = self._remediation_engine.generate_plan(
                root_cause=debate.verdict,
                confidence=debate.verdict_confidence,
                incident_id=incident_id,
            )

        if debate.verdict_confidence >= 0.7 and graph.nodes:
            sig = [n.label for n in list(graph.nodes.values())[:10]]
            self._knowledge_base.learn_from_incident(
                incident_id=incident_id,
                root_cause=debate.verdict,
                resolution=plan.steps[0].description if plan and plan.steps else "",
                signature=sig,
                category=self._extract_category(debate.verdict),
            )

        elapsed = (time.time() - start) * 1000

        return {
            "incident_id": incident_id,
            "status": "completed",
            "event_count": len(events),
            "cluster_result": cluster_result,
            "active_clusters": len(active_clusters),
            "correlations": len(correlations),
            "causal_graph": graph.to_dict(),
            "matched_patterns": len(matched_patterns),
            "debate": {
                "verdict": debate.verdict,
                "confidence": debate.verdict_confidence,
                "consensus": debate.is_consensus,
                "tokens": debate.total_tokens,
                "argument_count": len(debate.arguments),
            },
            "remediation": plan.to_dict() if plan else None,
            "duration_ms": elapsed,
        }

    def _form_hypothesis(
        self, graph: CausalGraph, patterns: list
    ) -> str:
        if patterns:
            return f"Possible known pattern: {patterns[0].name} — {patterns[0].description[:200]}"

        root = graph.get_root_cause()
        if root:
            return f"Hypothesis: root cause appears to be {root.label[:200]}"

        if graph.nodes:
            first = min(graph.nodes.values(), key=lambda n: n.timestamp)
            return f"Hypothesis: incident triggered by {first.label[:200]}"

        return "No hypothesis formed — insufficient data"

    @staticmethod
    def _extract_category(verdict: str) -> str:
        v = verdict.lower()
        if "kernel" in v:
            return "kernel"
        if "application" in v or "app" in v:
            return "application"
        if "infra" in v or "network" in v or "hardware" in v:
            return "infrastructure"
        if "change" in v or "deploy" in v:
            return "change_regression"
        return "uncategorized"
