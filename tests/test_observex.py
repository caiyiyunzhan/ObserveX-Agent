from __future__ import annotations

import json
import os
import tempfile
import time

import pytest

from observex.models.events import (
    RawEvent, ClusteredEvent, ChangeEvent,
    EventSource, EventSeverity, ChangeType,
)
from observex.models.causal import (
    CausalGraph, CausalNode, CausalEdge, NodeType, LinkType,
)
from observex.models.debate import (
    DebateSession, DebateArgument, DebatePhase, AgentRole, Evidence,
)
from observex.models.remediation import (
    RemediationPlan, RemediationStep, RemediationType,
    SandboxResult, VerificationStatus,
)
from observex.stream.ingestion import (
    parse_kmsg, parse_journald_json, parse_container_log,
    parse_ebpf_event, parse_structured_log, EventStreamProcessor,
)
from observex.processing.clustering import EventClusterer, CrossSourceCorrelator
from observex.processing.causal_builder import CausalGraphBuilder
from observex.agents.kernel_agent import KernelAgent
from observex.agents.application_agent import ApplicationAgent
from observex.agents.infra_agent import InfrastructureAgent
from observex.agents.change_agent import ChangeAgent
from observex.debate.engine import DebateEngine
from observex.remediation.engine import RemediationEngine
from observex.knowledge.base import KnowledgeBase, FailurePattern, KnowledgeEntry
from observex.pipeline import ObserveXPipeline


# ============================================================
# Event Model Tests
# ============================================================

class TestEventModels:
    def test_raw_event_defaults(self):
        evt = RawEvent()
        assert evt.event_id
        assert evt.source == EventSource.KERNEL
        assert evt.severity == EventSeverity.INFO

    def test_raw_event_fingerprint(self):
        evt1 = RawEvent(source=EventSource.KERNEL, service="test", severity=EventSeverity.ERROR, message="OOM killed")
        evt2 = RawEvent(source=EventSource.KERNEL, service="test", severity=EventSeverity.ERROR, message="OOM killed")
        assert evt1.fingerprint() == evt2.fingerprint()

    def test_raw_event_normalization(self):
        evt = RawEvent(message="Connection from 192.168.1.1 at 0xdeadbeef123456")
        fp = evt.fingerprint()
        assert "192.168.1.1" not in fp
        assert isinstance(fp, str)

    def test_clustered_event_to_dict(self):
        cluster = ClusteredEvent(cluster_id="c1", template="test", count=5, hosts={"h1", "h2"})
        d = cluster.to_dict()
        assert d["count"] == 5
        assert len(d["hosts"]) == 2

    def test_change_event_defaults(self):
        ce = ChangeEvent()
        assert ce.change_id
        assert ce.change_type == ChangeType.CODE_DEPLOY


# ============================================================
# Causal Graph Tests
# ============================================================

class TestCausalGraph:
    def test_add_node(self):
        g = CausalGraph()
        n = CausalNode(label="test", timestamp=100)
        nid = g.add_node(n)
        assert nid in g.nodes
        assert g.nodes[nid].label == "test"

    def test_add_edge(self):
        g = CausalGraph()
        n1 = CausalNode(label="a", timestamp=100)
        n2 = CausalNode(label="b", timestamp=200)
        g.add_node(n1)
        g.add_node(n2)
        edge = CausalEdge(source_node_id=n1.node_id, target_node_id=n2.node_id, confidence=0.8)
        g.add_edge(edge)
        assert len(g.edges) == 1

    def test_topological_order(self):
        g = CausalGraph()
        n1 = CausalNode(label="first", timestamp=100)
        n2 = CausalNode(label="second", timestamp=200)
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge(CausalEdge(source_node_id=n1.node_id, target_node_id=n2.node_id))
        order = g.topological_order()
        assert order[0].label == "first"
        assert order[1].label == "second"

    def test_get_incoming_edges(self):
        g = CausalGraph()
        n1 = CausalNode(label="a")
        n2 = CausalNode(label="b")
        g.add_node(n1)
        g.add_node(n2)
        g.add_edge(CausalEdge(source_node_id=n1.node_id, target_node_id=n2.node_id))
        assert len(g.get_incoming_edges(n2.node_id)) == 1
        assert len(g.get_incoming_edges(n1.node_id)) == 0

    def test_trace_causal_chain(self):
        g = CausalGraph()
        n1 = CausalNode(label="root")
        n2 = CausalNode(label="mid")
        n3 = CausalNode(label="leaf")
        g.add_node(n1)
        g.add_node(n2)
        g.add_node(n3)
        g.add_edge(CausalEdge(source_node_id=n1.node_id, target_node_id=n2.node_id))
        g.add_edge(CausalEdge(source_node_id=n2.node_id, target_node_id=n3.node_id))
        chains = g.trace_causal_chain(n3.node_id)
        assert len(chains) >= 1
        assert chains[0][-1].label == "root"

    def test_to_dict(self):
        g = CausalGraph(incident_id="inc-1")
        g.add_node(CausalNode(label="test"))
        d = g.to_dict()
        assert d["node_count"] == 1
        assert d["incident_id"] == "inc-1"

    def test_summary(self):
        g = CausalGraph()
        g.add_node(CausalNode(label="kernel panic", node_type=NodeType.ROOT_CAUSE))
        s = g.summary()
        assert "kernel panic" in s


# ============================================================
# Ingestion Parser Tests
# ============================================================

class TestIngestionParsers:
    def test_parse_kmsg(self):
        evt = parse_kmsg("[  123.456789] BUG: unable to handle kernel NULL pointer", host="h1")
        assert evt.source == EventSource.KERNEL
        assert evt.severity == EventSeverity.CRITICAL
        assert "BUG" in evt.message

    def test_parse_kmsg_info(self):
        evt = parse_kmsg("[  0.000000] Linux version 5.14.0")
        assert evt.severity == EventSeverity.INFO

    def test_parse_journald(self):
        record = {
            "MESSAGE": "Service started successfully",
            "PRIORITY": "6",
            "_SYSTEMD_UNIT": "nginx.service",
            "__REALTIME_TIMESTAMP": "1700000000000000",
        }
        evt = parse_journald_json(record, host="h1")
        assert evt.source == EventSource.APPLICATION
        assert evt.service == "nginx.service"

    def test_parse_container_log(self):
        evt = parse_container_log("ERROR Connection refused to database", host="h1", container="app-1")
        assert evt.source == EventSource.CONTAINER
        assert evt.severity == EventSeverity.ERROR

    def test_parse_ebpf_event(self):
        record = {"function": "tcp_connect", "pid": 1234, "timestamp": 1000.0}
        evt = parse_ebpf_event(record, host="h1")
        assert evt.source == EventSource.EBP
        assert "tcp_connect" in evt.message

    def test_parse_structured_log(self):
        data = {"level": "ERROR", "message": "DB connection failed", "service": "api", "trace_id": "abc123"}
        evt = parse_structured_log(data, host="h1")
        assert evt.severity == EventSeverity.ERROR
        assert evt.trace_id == "abc123"


# ============================================================
# Event Stream Processor Tests
# ============================================================

class TestEventStreamProcessor:
    def test_submit_and_stats(self):
        proc = EventStreamProcessor(batch_size=100, flush_interval=0.1)
        evt = RawEvent(message="test")
        assert proc.submit(evt) is True
        assert proc.stats["total_received"] == 1

    def test_batch_handler(self):
        proc = EventStreamProcessor(batch_size=2, flush_interval=10)
        batches = []
        proc.on_batch(lambda b: batches.append(b))
        proc.start()
        proc.submit(RawEvent(message="a"))
        proc.submit(RawEvent(message="b"))
        time.sleep(0.3)
        proc.stop()
        assert len(batches) >= 1
        assert len(batches[0]) == 2


# ============================================================
# Clustering Tests
# ============================================================

class TestClustering:
    def test_new_cluster(self):
        clusterer = EventClusterer()
        evt = RawEvent(source=EventSource.KERNEL, host="h1", message="OOM killed process 1234")
        cid, is_new = clusterer.ingest(evt)
        assert is_new is True
        assert cid.startswith("cl-")

    def test_merge_to_existing(self):
        clusterer = EventClusterer()
        evt1 = RawEvent(source=EventSource.KERNEL, host="h1", message="OOM killed process 1234")
        evt2 = RawEvent(source=EventSource.KERNEL, host="h2", message="OOM killed process 5678")
        cid1, _ = clusterer.ingest(evt1)
        cid2, is_new = clusterer.ingest(evt2)
        assert cid1 == cid2
        assert is_new is False

    def test_ingest_batch(self):
        clusterer = EventClusterer()
        events = [
            RawEvent(source=EventSource.KERNEL, message=f"error {i}") for i in range(10)
        ]
        result = clusterer.ingest_batch(events)
        assert result["processed"] == 10
        assert result["total_clusters"] > 0

    def test_multi_host_clusters(self):
        clusterer = EventClusterer()
        clusterer.ingest(RawEvent(source=EventSource.KERNEL, host="h1", message="panic"))
        clusterer.ingest(RawEvent(source=EventSource.KERNEL, host="h2", message="panic"))
        multi = clusterer.get_multi_host_clusters()
        assert len(multi) == 1
        assert len(multi[0].hosts) == 2


class TestCrossSourceCorrelator:
    def test_correlate_kernel_and_app(self):
        now = time.time()
        c1 = ClusteredEvent(
            cluster_id="k1", template="kernel panic",
            first_seen=now, sources={EventSource.KERNEL}, hosts={"h1"},
            severity=EventSeverity.CRITICAL,
        )
        c2 = ClusteredEvent(
            cluster_id="a1", template="connection timeout",
            first_seen=now + 0.5, sources={EventSource.APPLICATION}, hosts={"h1"},
            severity=EventSeverity.ERROR,
        )
        correlator = CrossSourceCorrelator(time_window_ms=5000)
        pairs = correlator.correlate([c1, c2])
        assert len(pairs) == 1
        assert pairs[0]["is_same_host"] is True

    def test_no_correlation_same_source(self):
        c1 = ClusteredEvent(
            cluster_id="k1", template="a", first_seen=100,
            sources={EventSource.KERNEL}, hosts={"h1"},
        )
        c2 = ClusteredEvent(
            cluster_id="k2", template="b", first_seen=100.1,
            sources={EventSource.KERNEL}, hosts={"h1"},
        )
        correlator = CrossSourceCorrelator()
        pairs = correlator.correlate([c1, c2])
        assert len(pairs) == 0


# ============================================================
# Causal Builder Tests
# ============================================================

class TestCausalBuilder:
    def test_build_simple_graph(self):
        now = time.time()
        clusters = [
            ClusteredEvent(
                cluster_id="k1", template="link down",
                first_seen=now, sources={EventSource.KERNEL}, hosts={"h1"},
                severity=EventSeverity.CRITICAL,
            ),
            ClusteredEvent(
                cluster_id="a1", template="timeout",
                first_seen=now + 2, sources={EventSource.APPLICATION}, hosts={"h1"},
                severity=EventSeverity.ERROR,
            ),
        ]
        builder = CausalGraphBuilder(incident_id="inc-1")
        graph = builder.build_from_correlations(clusters)
        assert len(graph.nodes) == 2
        assert len(graph.edges) >= 1

    def test_add_change_event(self):
        builder = CausalGraphBuilder()
        change = ChangeEvent(
            change_type=ChangeType.KERNEL_UPDATE,
            target_host="h1",
            description="Kernel update 5.14.0-284",
        )
        nid = builder.add_change_event(change)
        assert nid in builder._graph.nodes
        assert builder._graph.nodes[nid].node_type == NodeType.CHANGE


# ============================================================
# Agent Tests
# ============================================================

class TestAgents:
    def _make_graph(self, source: str, description: str) -> CausalGraph:
        g = CausalGraph()
        g.add_node(CausalNode(
            label=description, description=description,
            source=source, severity="critical", timestamp=time.time(),
        ))
        return g

    def test_kernel_agent_panic(self):
        graph = self._make_graph("kernel", "BUG: unable to handle kernel panic")
        agent = KernelAgent()
        arg = agent.analyze(graph, {})
        assert arg.agent_role == AgentRole.KERNEL
        assert arg.confidence > 0.7
        assert "panic" in arg.claim.lower()

    def test_application_agent_timeout(self):
        graph = self._make_graph("application", "Connection timeout to database")
        agent = ApplicationAgent()
        arg = agent.analyze(graph, {})
        assert arg.agent_role == AgentRole.APPLICATION
        assert "timeout" in arg.claim.lower()

    def test_infra_agent_network(self):
        graph = self._make_graph("infra", "Switch link down on port 24")
        agent = InfrastructureAgent()
        arg = agent.analyze(graph, {})
        assert arg.agent_role == AgentRole.INFRASTRUCTURE
        assert arg.confidence > 0.7

    def test_change_agent(self):
        graph = CausalGraph()
        graph.add_node(CausalNode(
            label="Kernel update", node_type=NodeType.CHANGE,
            description="Updated kernel 5.14.0-284", timestamp=time.time(),
        ))
        agent = ChangeAgent()
        arg = agent.analyze(graph, {})
        assert arg.agent_role == AgentRole.CHANGE
        assert arg.confidence > 0.5

    def test_agents_no_data(self):
        graph = CausalGraph()
        for AgentCls in [KernelAgent, ApplicationAgent, InfrastructureAgent, ChangeAgent]:
            arg = AgentCls().analyze(graph, {})
            assert arg.confidence < 0.2


# ============================================================
# Debate Engine Tests
# ============================================================

class TestDebateEngine:
    def test_full_debate(self):
        graph = CausalGraph()
        now = time.time()
        graph.add_node(CausalNode(
            label="kernel panic", description="BUG: null pointer",
            source="kernel", severity="critical", timestamp=now,
        ))
        graph.add_node(CausalNode(
            label="app timeout", description="Connection timeout",
            source="application", severity="error", timestamp=now + 1,
        ))

        engine = DebateEngine(rounds=2)
        session = engine.run(graph, incident_id="inc-1", hypothesis="Kernel panic caused app timeout")

        assert session.verdict
        assert session.verdict_confidence > 0
        assert len(session.arguments) == 8
        assert session.total_tokens >= 0

    def test_debate_transcript(self):
        graph = CausalGraph()
        graph.add_node(CausalNode(label="test", source="kernel"))
        engine = DebateEngine(rounds=1)
        session = engine.run(graph)
        transcript = session.transcript()
        assert "VERDICT" in transcript

    def test_debate_to_dict(self):
        graph = CausalGraph()
        graph.add_node(CausalNode(label="test", source="kernel"))
        engine = DebateEngine(rounds=1)
        session = engine.run(graph)
        d = session.to_dict()
        assert "verdict" in d
        assert "arguments" in d


# ============================================================
# Remediation Engine Tests
# ============================================================

class TestRemediationEngine:
    def test_generate_null_deref_plan(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("NULL dereference in mlx5_poll_cq+0x124", 0.85)
        assert len(plan.steps) >= 1
        assert any(s.step_type == RemediationType.EBP_PATCH for s in plan.steps)

    def test_generate_timeout_plan(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("Connection timeout to database", 0.7)
        assert any(s.step_type == RemediationType.KERNEL_PARAM for s in plan.steps)

    def test_generate_oom_plan(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("OOM killed process, memory exhausted", 0.8)
        assert any("overcommit" in s.command for s in plan.steps if s.command)

    def test_generate_network_plan(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("Switch link down, packet loss on eth0", 0.75)
        assert any(s.step_type == RemediationType.JIRA_TICKET for s in plan.steps)

    def test_verify_sysctl(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("timeout", 0.7)
        result = engine.verify_in_sandbox(plan, step_index=0)
        assert result.status in (VerificationStatus.PASSED, VerificationStatus.SKIPPED)

    def test_plan_to_dict(self):
        engine = RemediationEngine()
        plan = engine.generate_plan("NULL deref in func", 0.8)
        d = plan.to_dict()
        assert "steps" in d
        assert d["step_count"] >= 1


# ============================================================
# Knowledge Base Tests
# ============================================================

class TestKnowledgeBase:
    def test_add_and_match_pattern(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = KnowledgeBase(kb_dir=tmpdir)
            kb.add_pattern(FailurePattern(
                name="Kernel OOM",
                signature=["oom", "kernel", "memory"],
                root_cause_category="kernel",
            ))
            matches = kb.match_pattern(["oom", "kernel", "memory", "killed"])
            assert len(matches) == 1
            assert matches[0].name == "Kernel OOM"

    def test_pattern_occurrence_increment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = KnowledgeBase(kb_dir=tmpdir)
            p = FailurePattern(name="test", signature=["a", "b"])
            kb.add_pattern(p)
            kb.add_pattern(p)
            assert kb._patterns[p.pattern_id].occurrence_count == 2

    def test_learn_from_incident(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = KnowledgeBase(kb_dir=tmpdir)
            pid = kb.learn_from_incident(
                incident_id="inc-1",
                root_cause="NULL deref",
                resolution="Add NULL check",
                signature=["null", "deref", "mlx5"],
                category="kernel",
            )
            assert pid
            assert kb.stats["patterns"] == 1
            assert kb.stats["entries"] == 1

    def test_search_entries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = KnowledgeBase(kb_dir=tmpdir)
            kb.add_entry(KnowledgeEntry(
                title="OOM Resolution",
                content="Increase memory limits",
                tags=["kernel", "oom"],
            ))
            results = kb.search_entries("OOM")
            assert len(results) == 1

    def test_summarize_patterns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            kb = KnowledgeBase(kb_dir=tmpdir)
            kb.add_pattern(FailurePattern(name="p1", signature=["a"], root_cause_category="kernel"))
            kb.add_pattern(FailurePattern(name="p2", signature=["b"], root_cause_category="app"))
            summary = kb.summarize_patterns()
            assert summary["total_patterns"] == 2
            assert "kernel" in summary["categories"]


# ============================================================
# Full Pipeline Tests
# ============================================================

class TestObserveXPipeline:
    def test_end_to_end(self):
        now = time.time()
        events = [
            RawEvent(
                event_id=f"e{i}", timestamp=now + i * 0.1,
                source=source, host="h1",
                severity=severity, message=msg,
            )
            for i, (source, severity, msg) in enumerate([
                (EventSource.KERNEL, EventSeverity.CRITICAL, "BUG: unable to handle kernel NULL pointer"),
                (EventSource.KERNEL, EventSeverity.ERROR, "softlockup on CPU 3"),
                (EventSource.APPLICATION, EventSeverity.ERROR, "Connection timeout to database"),
                (EventSource.CONTAINER, EventSeverity.WARNING, "Memory limit approaching 90%"),
                (EventSource.APPLICATION, EventSeverity.CRITICAL, "OOM killed process 5678"),
            ])
        ]

        changes = [
            ChangeEvent(
                change_type=ChangeType.KERNEL_UPDATE,
                target_host="h1",
                description="Kernel update 5.14.0-284 -> 5.14.0-285",
                timestamp=now - 3600,
            ),
        ]

        pipeline = ObserveXPipeline(debate_rounds=1, enable_remediation=True, kb_dir=tempfile.mkdtemp())
        result = pipeline.process_events(events, changes=changes, incident_id="test-inc-1")

        assert result["incident_id"] == "test-inc-1"
        assert result["event_count"] == 5
        assert result["active_clusters"] > 0
        assert result["debate"]["verdict"]
        assert result["debate"]["confidence"] > 0
        assert result["causal_graph"]["node_count"] > 0

    def test_empty_events(self):
        pipeline = ObserveXPipeline(kb_dir=tempfile.mkdtemp())
        result = pipeline.process_events([])
        assert result["event_count"] == 0
        assert result["debate"]["verdict"]
