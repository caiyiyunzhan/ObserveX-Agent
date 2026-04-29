from __future__ import annotations

import time
from typing import Any

from observex.models.events import ClusteredEvent, ChangeEvent
from observex.models.causal import (
    CausalGraph, CausalNode, CausalEdge, NodeType, LinkType,
)
from observex.processing.clustering import CrossSourceCorrelator


class CausalGraphBuilder:
    def __init__(
        self,
        incident_id: str = "",
        time_window_s: float = 1800,
    ) -> None:
        self._incident_id = incident_id
        self._window_s = time_window_s
        self._graph = CausalGraph(incident_id=incident_id)

    def add_event_cluster(self, cluster: ClusteredEvent) -> str:
        node = CausalNode(
            node_type=NodeType.EVENT,
            label=f"{cluster.sources} {cluster.template[:80]}",
            description=cluster.template,
            timestamp=cluster.first_seen,
            host=", ".join(list(cluster.hosts)[:3]),
            source=", ".join(s.value for s in cluster.sources),
            severity=cluster.severity.value,
            evidence=[
                f"count={cluster.count}",
                f"hosts={len(cluster.hosts)}",
            ],
            metadata={"cluster_id": cluster.cluster_id},
        )
        return self._graph.add_node(node)

    def add_change_event(self, change: ChangeEvent) -> str:
        node = CausalNode(
            node_type=NodeType.CHANGE,
            label=f"{change.change_type.value}: {change.target_service}",
            description=change.description,
            timestamp=change.timestamp,
            host=change.target_host,
            service=change.target_service,
            source=change.source_system,
            evidence=[
                f"old={change.old_value}",
                f"new={change.new_value}",
                f"by={change.operator}",
            ],
        )
        return self._graph.add_node(node)

    def add_metric_anomaly(
        self, name: str, value: float, threshold: float,
        timestamp: float, host: str, service: str = "",
    ) -> str:
        node = CausalNode(
            node_type=NodeType.METRIC_ANOMALY,
            label=f"{name} = {value:.2f} (threshold={threshold:.2f})",
            description=f"{name} exceeded threshold",
            timestamp=timestamp,
            host=host,
            service=service,
            source="prometheus",
            evidence=[f"value={value}", f"threshold={threshold}", f"ratio={value/threshold:.2f}x"],
        )
        return self._graph.add_node(node)

    def infer_temporal_edges(self, max_time_gap_s: float = 300) -> int:
        nodes_by_time = sorted(self._graph.nodes.values(), key=lambda n: n.timestamp)
        edges_added = 0

        for i, earlier in enumerate(nodes_by_time):
            for later in nodes_by_time[i + 1:]:
                gap = later.timestamp - earlier.timestamp
                if gap > max_time_gap_s:
                    break

                if gap <= 0:
                    continue

                confidence = max(0.1, 1.0 - (gap / max_time_gap_s))

                if earlier.host and later.host and earlier.host == later.host:
                    confidence *= 1.3
                if earlier.service and later.service and earlier.service == later.service:
                    confidence *= 1.2

                if earlier.node_type == NodeType.CHANGE:
                    confidence *= 1.4

                confidence = min(confidence, 1.0)

                if confidence >= 0.3:
                    edge = CausalEdge(
                        source_node_id=earlier.node_id,
                        target_node_id=later.node_id,
                        link_type=LinkType.PRECEDES if confidence < 0.6 else LinkType.CAUSES,
                        confidence=confidence,
                        reasoning=f"Temporal: {gap:.1f}s gap, same_host={earlier.host == later.host}",
                    )
                    self._graph.add_edge(edge)
                    edges_added += 1

        return edges_added

    def infer_change_impact_edges(self, events: list[ClusteredEvent], changes: list[ChangeEvent]) -> int:
        edges_added = 0
        for change in changes:
            change_node = self._find_change_node(change)
            if not change_node:
                continue
            for event in events:
                if event.first_seen < change.timestamp:
                    continue
                gap = event.first_seen - change.timestamp
                if gap > self._window_s:
                    continue
                if change.target_host and change.target_host in event.hosts:
                    edge = CausalEdge(
                        source_node_id=change_node.node_id,
                        target_node_id=self._find_event_node_id(event),
                        link_type=LinkType.TRIGGERS,
                        confidence=min(0.9, 0.5 + (1.0 - gap / self._window_s) * 0.4),
                        reasoning=f"Change on {change.target_host} preceded event by {gap:.1f}s",
                    )
                    self._graph.add_edge(edge)
                    edges_added += 1
        return edges_added

    def _find_change_node(self, change: ChangeEvent) -> CausalNode | None:
        for node in self._graph.nodes.values():
            if node.node_type == NodeType.CHANGE and change.description in node.description:
                return node
        return None

    def _find_event_node_id(self, cluster: ClusteredEvent) -> str:
        for node in self._graph.nodes.values():
            if node.metadata.get("cluster_id") == cluster.cluster_id:
                return node.node_id
        return ""

    def mark_root_cause(self, node_id: str, confidence: float) -> None:
        if node_id in self._graph.nodes:
            self._graph.root_cause_node_id = node_id
            self._graph.nodes[node_id].node_type = NodeType.ROOT_CAUSE
            self._graph.nodes[node_id].metadata["root_cause_confidence"] = confidence

    def get_graph(self) -> CausalGraph:
        return self._graph

    def build_from_correlations(
        self,
        clusters: list[ClusteredEvent],
        changes: list[ChangeEvent] | None = None,
    ) -> CausalGraph:
        node_map: dict[str, str] = {}
        for cluster in clusters:
            nid = self.add_event_cluster(cluster)
            node_map[cluster.cluster_id] = nid

        if changes:
            for change in changes:
                self.add_change_event(change)

        self.infer_temporal_edges()

        if changes:
            self.infer_change_impact_edges(clusters, changes)

        if not self._graph.root_cause_node_id and self._graph.nodes:
            best = max(
                self._graph.nodes.values(),
                key=lambda n: len(self._graph.get_incoming_edges(n.node_id)) == 0
                and n.timestamp or 0,
            )
            self.mark_root_cause(best.node_id, 0.5)

        return self._graph
