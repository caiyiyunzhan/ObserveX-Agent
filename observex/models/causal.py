from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    EVENT = "event"
    CHANGE = "change"
    METRIC_ANOMALY = "metric_anomaly"
    INFRA_STATE = "infra_state"
    ROOT_CAUSE = "root_cause"
    SYMPTOM = "symptom"


class LinkType(str, Enum):
    CAUSES = "causes"
    TRIGGERS = "triggers"
    PRECEDES = "precedes"
    CORRELATES = "correlates"
    MITIGATED_BY = "mitigated_by"


@dataclass
class CausalNode:
    node_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    node_type: NodeType = NodeType.EVENT
    label: str = ""
    description: str = ""
    timestamp: float = 0.0
    host: str = ""
    service: str = ""
    source: str = ""
    severity: str = ""
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "type": self.node_type.value,
            "label": self.label,
            "description": self.description,
            "timestamp": self.timestamp,
            "host": self.host,
            "service": self.service,
            "source": self.source,
            "severity": self.severity,
            "evidence": self.evidence,
        }


@dataclass
class CausalEdge:
    edge_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    source_node_id: str = ""
    target_node_id: str = ""
    link_type: LinkType = LinkType.CORRELATES
    confidence: float = 0.0
    reasoning: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source_node_id,
            "target": self.target_node_id,
            "type": self.link_type.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


@dataclass
class CausalGraph:
    graph_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    incident_id: str = ""
    nodes: dict[str, CausalNode] = field(default_factory=dict)
    edges: list[CausalEdge] = field(default_factory=list)
    root_cause_node_id: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0

    def add_node(self, node: CausalNode) -> str:
        self.nodes[node.node_id] = node
        return node.node_id

    def add_edge(self, edge: CausalEdge) -> None:
        self.edges.append(edge)

    def get_root_cause(self) -> CausalNode | None:
        if self.root_cause_node_id:
            return self.nodes.get(self.root_cause_node_id)
        return None

    def get_incoming_edges(self, node_id: str) -> list[CausalEdge]:
        return [e for e in self.edges if e.target_node_id == node_id]

    def get_outgoing_edges(self, node_id: str) -> list[CausalEdge]:
        return [e for e in self.edges if e.source_node_id == node_id]

    def trace_causal_chain(self, node_id: str, max_depth: int = 10) -> list[list[CausalNode]]:
        chains: list[list[CausalNode]] = []
        self._dfs_chains(node_id, [self.nodes[node_id]], chains, set(), max_depth)
        return chains

    def _dfs_chains(
        self, current_id: str, path: list[CausalNode],
        chains: list[list[CausalNode]], visited: set[str], depth: int
    ) -> None:
        if depth <= 0:
            return
        incoming = self.get_incoming_edges(current_id)
        if not incoming:
            chains.append(list(path))
            return
        for edge in incoming:
            if edge.source_node_id in visited:
                continue
            visited.add(edge.source_node_id)
            node = self.nodes.get(edge.source_node_id)
            if node:
                path.append(node)
                self._dfs_chains(edge.source_node_id, path, chains, visited, depth - 1)
                path.pop()
            visited.discard(edge.source_node_id)

    def topological_order(self) -> list[CausalNode]:
        in_degree: dict[str, int] = {nid: 0 for nid in self.nodes}
        for edge in self.edges:
            if edge.target_node_id in in_degree:
                in_degree[edge.target_node_id] += 1

        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        order: list[CausalNode] = []

        while queue:
            nid = queue.pop(0)
            node = self.nodes.get(nid)
            if node:
                order.append(node)
            for edge in self.get_outgoing_edges(nid):
                if edge.target_node_id in in_degree:
                    in_degree[edge.target_node_id] -= 1
                    if in_degree[edge.target_node_id] == 0:
                        queue.append(edge.target_node_id)

        return order

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "incident_id": self.incident_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "root_cause": self.get_root_cause().to_dict() if self.get_root_cause() else None,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "chain_length": len(self.topological_order()),
        }

    def summary(self) -> str:
        order = self.topological_order()
        lines = [f"CausalGraph [{self.graph_id}]: {len(self.nodes)} nodes, {len(self.edges)} edges"]
        for node in order:
            incoming = self.get_incoming_edges(node.node_id)
            if incoming:
                best = max(incoming, key=lambda e: e.confidence)
                lines.append(
                    f"  <-[{best.link_type.value} {best.confidence:.2f}]-> "
                    f"{node.node_type.value}: {node.label}"
                )
            else:
                lines.append(f"  ROOT: {node.node_type.value}: {node.label}")
        return "\n".join(lines)
