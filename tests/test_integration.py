from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kcrash.collector.vmcore_reader import VMCoreReader
from kcrash.collector.change_fetcher import ChangeFetcher, Change, CrashRecord
from kcrash.collector.hw_errors import HWErrorCollector, HWError
from kcrash.agents.base_agent import Argument
from kcrash.agents.symbol_agent import SymbolAgent
from kcrash.agents.change_agent import ChangeAgent
from kcrash.agents.hardware_agent import HardwareAgent
from kcrash.debate.moderator import DebateModerator
from kcrash.debate.memory import DebateMemory
from kcrash.patch.validator import EbpfValidator
from kcrash.patch.generator import EbpfGenerator, TEMPLATE_MAP
from kcrash.patch.kpatch import KpatchGenerator, KPATCH_TEMPLATE, KPATCH_MAKEFILE
from kcrash.core.fingerprint import (
    generate_fingerprint, classify_error, is_similar, CrashFingerprint
)
from kcrash.core.severity import assess_severity, Severity, SeverityAssessment
from kcrash.core.cache import AnalysisCache
from kcrash.core.ingestion import CrashIngestion, CrashEvent
from kcrash.core.report import AnalysisReport
from kcrash.utils.token_counter import TokenCounter, get_token_counter
from kcrash.utils.config import load_config, AppConfig


FIXTURES_DIR = Path(__file__).parent / "fixtures"
MOCK_PATH = FIXTURES_DIR / "mock_vmcore.json"


@pytest.fixture(autouse=True)
def ensure_mock_data():
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    if not MOCK_PATH.exists():
        from scripts.mock_vmcore_info import MOCK_DATA
        with open(MOCK_PATH, "w") as f:
            json.dump(MOCK_DATA, f, indent=2, default=str)
    yield
    cache_dir = Path(".kcrash_cache")
    if cache_dir.exists():
        import shutil
        shutil.rmtree(cache_dir, ignore_errors=True)


# ============================================================
# VMCoreReader Tests
# ============================================================

class TestVMCoreReader:
    def test_get_panic_stack_from_mock(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        frames = reader.get_panic_stack()
        assert len(frames) == 5
        assert frames[0].function == "mlx5_poll_cq"
        assert frames[0].offset == 0x124
        assert frames[0].module == "mlx5_core"

    def test_read_kernel_log_from_mock(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        log = reader.read_kernel_log()
        assert "mlx5_poll_cq" in log
        assert "BUG: unable to handle page fault" in log
        assert "CPU: 12" in log

    def test_dereference_chain_from_mock(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        chain = reader.dereference_chain(0xFFFFFFFFC0A2D124, "struct page")
        assert "members" in chain
        assert "flags" in chain["members"]

    def test_dereference_chain_invalid_address(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        chain = reader.dereference_chain(0xDEAD, "struct page")
        assert chain == {}

    def test_frame_source_line(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        frames = reader.get_panic_stack()
        assert "cq.c:342" in frames[0].source_line

    def test_stack_depth(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        frames = reader.get_panic_stack()
        assert all(f.function for f in frames)
        assert all(isinstance(f.ip, int) for f in frames)


# ============================================================
# ChangeFetcher Tests
# ============================================================

class TestChangeFetcher:
    def test_get_recent_changes_with_mock(self):
        mock = {"recent_changes": [
            {"type": "rpm", "name": "kernel", "old": "5.14.0-283", "new": "5.14.0-284"},
            {"type": "rpm", "name": "mlx5_core", "old": "5.14-1", "new": "5.14-2"},
        ]}
        fetcher = ChangeFetcher(mock_data=mock)
        changes = fetcher.get_recent_changes("host-01")
        assert len(changes) == 2
        assert changes[0].change_type == "rpm"
        assert changes[1].name == "mlx5_core"

    def test_get_recent_changes_empty(self):
        fetcher = ChangeFetcher(mock_data={"recent_changes": []})
        changes = fetcher.get_recent_changes("host-01")
        assert len(changes) == 0

    def test_get_sibling_crashes_with_mock(self):
        mock = {"sibling_crashes": [
            {
                "hostname": "host-02",
                "function": "mlx5_poll_cq",
                "offset": 0x120,
                "error_type": "page_fault",
                "timestamp": "2024-01-15T03:22:10Z",
            },
            {
                "hostname": "host-05",
                "function": "mlx5_napi_poll",
                "offset": 0x90,
                "error_type": "null_deref",
                "timestamp": "2024-02-01T11:45:33Z",
            },
        ]}
        fetcher = ChangeFetcher(mock_data=mock)
        crashes = fetcher.get_sibling_crashes("host-*")
        assert len(crashes) == 2
        assert crashes[0].error_type == "page_fault"

    def test_fallback_behavior(self):
        fetcher = ChangeFetcher(mock_data=None)
        changes = fetcher.get_recent_changes("host-01")
        assert isinstance(changes, list)


# ============================================================
# HWErrorCollector Tests
# ============================================================

class TestHWErrorCollector:
    def test_collect_with_mock_mcelog(self):
        mock = {"mcelog_errors": [
            {"source": "mcelog", "severity": "critical", "message": "MCE bank 5 corrected"}
        ]}
        collector = HWErrorCollector(mock_data=mock)
        errors = collector.collect_all()
        assert len(errors) >= 1
        assert errors[0].source == "mcelog"

    def test_collect_with_mock_edac(self):
        mock = {"edac_errors": [
            {"source": "edac", "severity": "warning", "message": "CE on mc0"}
        ]}
        collector = HWErrorCollector(mock_data=mock)
        errors = collector.collect_all()
        assert any(e.source == "edac" for e in errors)

    def test_collect_empty(self):
        mock = {"mcelog_errors": [], "smartctl_errors": [], "edac_errors": []}
        collector = HWErrorCollector(mock_data=mock)
        errors = collector.collect_all()
        assert errors == []


# ============================================================
# Fingerprint Tests
# ============================================================

class TestFingerprint:
    def _make_frames(self):
        reader = VMCoreReader(str(MOCK_PATH), "dummy")
        return reader.get_panic_stack()

    def test_generate_fingerprint(self):
        frames = self._make_frames()
        dmesg = "Oops: 0000 [#1] SMP PTI"
        fp = generate_fingerprint(frames, dmesg)
        assert fp.hash_value != "empty"
        assert fp.top_function == "mlx5_poll_cq"
        assert fp.error_class == "kernel_oops"
        assert fp.module == "mlx5_core"
        assert len(fp.stack_signature) == 5

    def test_fingerprint_empty_frames(self):
        fp = generate_fingerprint([], "")
        assert fp.hash_value == "empty"
        assert fp.depth == 0

    def test_fingerprint_consistency(self):
        frames = self._make_frames()
        fp1 = generate_fingerprint(frames, "Oops")
        fp2 = generate_fingerprint(frames, "Oops")
        assert fp1.hash_value == fp2.hash_value

    def test_fingerprint_to_dict(self):
        frames = self._make_frames()
        fp = generate_fingerprint(frames, "BUG")
        d = fp.to_dict()
        assert "hash" in d
        assert "top_function" in d
        assert "stack_signature" in d

    def test_classify_error_patterns(self):
        assert classify_error("BUG: unable to handle kernel NULL pointer") == "kernel_bug"
        assert classify_error("Oops: 0000 [#1]") == "kernel_oops"
        assert classify_error("unable to handle page fault") == "page_fault"
        assert classify_error("general protection fault") == "gpf"
        assert classify_error("kernel panic - not syncing") == "panic"
        assert classify_error("divide error") == "divide_error"
        assert classify_error("random message") == "unknown"

    def test_is_similar_identical(self):
        frames = self._make_frames()
        fp = generate_fingerprint(frames, "Oops")
        assert is_similar(fp, fp, threshold=0.5) is True

    def test_is_similar_different(self):
        frames = self._make_frames()
        fp1 = generate_fingerprint(frames, "Oops")
        fp2 = generate_fingerprint([], "")
        assert is_similar(fp1, fp2) is False


# ============================================================
# Severity Tests
# ============================================================

class TestSeverity:
    def _make_fingerprint(self, error_class="null_deref"):
        return CrashFingerprint(
            hash_value="abc123",
            top_function="mlx5_poll_cq",
            error_class=error_class,
            module="mlx5_core",
            stack_signature=["mlx5_poll_cq+0x124"],
            depth=5,
        )

    def test_critical_severity(self):
        fp = self._make_fingerprint("kernel_panic")
        hw = [{"severity": "critical", "source": "mcelog", "message": "MCE"}]
        result = assess_severity(fp, [], hw, sibling_crash_count=3)
        assert result.level == Severity.CRITICAL
        assert result.score >= 80

    def test_low_severity(self):
        fp = CrashFingerprint(
            hash_value="low",
            top_function="minor_func",
            error_class="unknown",
            module="",
            stack_signature=["minor_func+0x10"],
            depth=1,
        )
        result = assess_severity(fp, [], [], sibling_crash_count=0)
        assert result.level == Severity.LOW
        assert result.score < 35

    def test_severity_with_critical_module(self):
        fp = self._make_fingerprint("null_deref")
        fp.module = "nvme"
        result = assess_severity(fp, [], [], sibling_crash_count=0)
        assert result.score > 30

    def test_severity_has_factors(self):
        fp = self._make_fingerprint("gpf")
        result = assess_severity(fp, [], [], sibling_crash_count=0)
        assert len(result.factors) > 0
        assert result.sla_impact
        assert result.recommended_action

    def test_severity_enum_labels(self):
        assert Severity.LOW.label() == "LOW"
        assert Severity.MEDIUM.label() == "MEDIUM"
        assert Severity.HIGH.label() == "HIGH"
        assert Severity.CRITICAL.label() == "CRITICAL"


# ============================================================
# Cache Tests
# ============================================================

class TestCache:
    def test_set_and_get(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir, ttl_seconds=60)
            key = AnalysisCache.make_key("abc123")
            cache.set(key, {"result": "test"})
            assert cache.get(key) == {"result": "test"}

    def test_cache_miss(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)
            assert cache.get("nonexistent") is None

    def test_cache_expiry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir, ttl_seconds=0)
            key = AnalysisCache.make_key("abc")
            cache.set(key, {"data": 1})
            time.sleep(0.1)
            assert cache.get(key) is None

    def test_cache_stats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)
            assert cache.stats["entries"] == 0
            key = AnalysisCache.make_key("x")
            cache.set(key, {"v": 1})
            assert cache.stats["entries"] == 1

    def test_cache_clear(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = AnalysisCache(cache_dir=tmpdir)
            cache.set("a", {"v": 1})
            cache.set("b", {"v": 2})
            cache.clear()
            assert cache.stats["entries"] == 0


# ============================================================
# Agent Tests
# ============================================================

class TestAgents:
    def _make_context(self):
        return {
            "panic_point": "mlx5_poll_cq+0x124",
            "error_class": "null_deref",
            "evidence": ["RDI=0x0", "page->mapping is NULL"],
            "confidence": 0.8,
            "root_cause_candidates": [
                {
                    "claim": "NULL deref in mlx5 driver after update",
                    "probability": 0.75,
                    "evidence_chain": ["Recent mlx5_core update"],
                }
            ],
            "_collected_changes": [
                {"type": "rpm", "name": "mlx5_core", "old": "5.14-1", "new": "5.14-2"}
            ],
            "_hw_errors": [],
        }

    def test_symbol_agent_initial_argument(self):
        agent = SymbolAgent()
        ctx = self._make_context()
        arg = agent.initial_argument(ctx)
        assert arg.agent_name == "SymbolAgent"
        assert arg.confidence == 0.8
        assert "mlx5_poll_cq" in arg.claim
        assert len(arg.evidences) >= 2

    def test_symbol_agent_rebut_low_confidence_opponent(self):
        agent = SymbolAgent()
        ctx = self._make_context()
        opponents = [
            Argument(agent_name="ChangeAgent", claim="change cause", confidence=0.3, evidences=[])
        ]
        arg = agent.rebut(opponents, ctx)
        assert arg.confidence > 0.6

    def test_symbol_agent_rebut_high_confidence_opponent(self):
        agent = SymbolAgent()
        ctx = self._make_context()
        opponents = [
            Argument(agent_name="ChangeAgent", claim="change cause", confidence=0.9, evidences=[])
        ]
        arg = agent.rebut(opponents, ctx)
        assert arg.confidence < 0.8

    def test_change_agent_initial_argument(self):
        agent = ChangeAgent()
        ctx = self._make_context()
        arg = agent.initial_argument(ctx)
        assert arg.agent_name == "ChangeAgent"
        assert arg.confidence > 0

    def test_change_agent_no_candidates(self):
        agent = ChangeAgent()
        ctx = {"root_cause_candidates": [], "_collected_changes": []}
        arg = agent.initial_argument(ctx)
        assert arg.confidence < 0.2

    def test_hardware_agent_with_critical_errors(self):
        agent = HardwareAgent()
        ctx = {
            "_hw_errors": [
                {"source": "mcelog", "severity": "critical", "message": "MCE error"},
                {"source": "edac", "severity": "critical", "message": "UE detected"},
            ]
        }
        arg = agent.initial_argument(ctx)
        assert arg.confidence == 0.8
        assert "hardware" in arg.claim.lower()

    def test_hardware_agent_no_errors(self):
        agent = HardwareAgent()
        ctx = {"_hw_errors": []}
        arg = agent.initial_argument(ctx)
        assert arg.confidence < 0.2

    def test_hardware_agent_warning_only(self):
        agent = HardwareAgent()
        ctx = {"_hw_errors": [
            {"source": "edac", "severity": "warning", "message": "CE count > 0"}
        ]}
        arg = agent.initial_argument(ctx)
        assert 0.3 <= arg.confidence <= 0.5

    def test_agent_rebuttal_preserves_name(self):
        for AgentClass in [SymbolAgent, ChangeAgent, HardwareAgent]:
            agent = AgentClass()
            ctx = {"_hw_errors": [], "_collected_changes": [], "root_cause_candidates": [],
                   "panic_point": "test", "error_class": "test", "evidence": [], "confidence": 0.5}
            opponent = Argument(agent_name="Other", claim="test", confidence=0.5)
            arg = agent.rebut([opponent], ctx)
            assert arg.agent_name == agent.name


# ============================================================
# Debate Tests
# ============================================================

class TestDebate:
    def _make_context(self):
        return {
            "panic_point": "mlx5_poll_cq+0x124",
            "error_class": "null_deref",
            "evidence": ["RDI=0x0"],
            "confidence": 0.8,
            "root_cause_candidates": [
                {"claim": "NULL deref in mlx5", "probability": 0.7, "evidence_chain": ["Recent update"]}
            ],
            "_collected_changes": [],
            "_hw_errors": [],
        }

    def test_full_debate_two_rounds(self):
        agents = [SymbolAgent(), ChangeAgent(), HardwareAgent()]
        moderator = DebateModerator(agents, rounds=2)
        result = moderator.conduct(self._make_context())
        assert "verdict" in result
        assert "final_confidence" in result
        assert "transcript" in result
        assert "round_details" in result
        assert result["final_confidence"] > 0
        assert len(result["transcript"]) > 100

    def test_debate_verdict_has_agent_name(self):
        agents = [SymbolAgent(), ChangeAgent()]
        moderator = DebateModerator(agents, rounds=1)
        result = moderator.conduct(self._make_context())
        assert result["verdict"].agent_name in ["SymbolAgent", "ChangeAgent"]

    def test_debate_round_details_count(self):
        agents = [SymbolAgent(), ChangeAgent(), HardwareAgent()]
        moderator = DebateModerator(agents, rounds=2)
        result = moderator.conduct(self._make_context())
        # Round 1: 3 initial, Round 2: 3 rebut
        assert len(result["round_details"]) == 6

    def test_debate_memory(self):
        memory = DebateMemory()
        arg1 = Argument(agent_name="A", claim="c1", confidence=0.5, evidences=["e1"])
        arg2 = Argument(agent_name="B", claim="c2", confidence=0.6, evidences=["e2"])
        memory.record(1, "initial", "A", arg1)
        memory.record(1, "initial", "B", arg2)

        transcript = memory.transcript()
        assert "A" in transcript
        assert "B" in transcript
        assert "c1" in transcript

        opponents = memory.get_opponent_arguments("A", 1)
        assert len(opponents) == 1
        assert opponents[0].agent_name == "B"

        round_args = memory.get_round_arguments(1)
        assert len(round_args) == 2

    def test_debate_memory_to_dict(self):
        memory = DebateMemory()
        arg = Argument(agent_name="A", claim="test", confidence=0.5)
        memory.record(1, "initial", "A", arg)
        d = memory.to_dict()
        assert len(d) == 1
        assert d[0]["agent"] == "A"


# ============================================================
# eBPF Generator Tests
# ============================================================

class TestEbpfGenerator:
    def test_generate_null_deref_template(self):
        gen = EbpfGenerator()
        verdict = Argument(
            agent_name="Test",
            claim="NULL deref in mlx5_poll_cq",
            confidence=0.8,
            evidences=["Panic at mlx5_poll_cq+0x124"],
        )
        code = gen.generate(verdict, template="null_deref")
        assert "mlx5_poll_cq" in code
        assert "BPF_HASH" in code
        assert "bpf_trace_printk" in code

    def test_generate_page_fault_template(self):
        gen = EbpfGenerator()
        verdict = Argument(
            agent_name="Test",
            claim="page fault in target_func",
            confidence=0.8,
            evidences=["Panic at target_func+0x100"],
        )
        code = gen.generate(verdict, template="page_fault")
        assert "target_func" in code
        assert "NULL" in code or "addr == 0" in code

    def test_generate_race_condition_template(self):
        gen = EbpfGenerator()
        verdict = Argument(
            agent_name="Test",
            claim="race condition in lock_acquire",
            confidence=0.7,
            evidences=["Panic at lock_acquire+0x50"],
        )
        code = gen.generate(verdict, template="race_condition")
        assert "lock_acquire" in code
        assert "contention" in code

    def test_generate_smart_skeleton_null(self):
        gen = EbpfGenerator()
        verdict = Argument(
            agent_name="Test",
            claim="NULL pointer dereference",
            confidence=0.8,
            evidences=["Panic at my_func+0x100"],
        )
        code = gen.generate(verdict)
        assert "my_func" in code
        assert "BPF_" in code

    def test_classify_error(self):
        assert EbpfGenerator._classify_error("NULL deref") == "null_deref"
        assert EbpfGenerator._classify_error("page fault detected") == "page_fault"
        assert EbpfGenerator._classify_error("memory leak in kmalloc") == "memory_leak"
        assert EbpfGenerator._classify_error("race condition in lock") == "race_condition"
        assert EbpfGenerator._classify_error("something else") == "generic"

    def test_all_templates_have_func_name(self):
        gen = EbpfGenerator()
        verdict = Argument(
            agent_name="Test", claim="test", confidence=0.5,
            evidences=["Panic at test_func+0x10"],
        )
        for template_name in TEMPLATE_MAP:
            code = gen.generate(verdict, template=template_name)
            assert "test_func" in code, f"Template {template_name} missing function name"


# ============================================================
# Kpatch Generator Tests
# ============================================================

class TestKpatchGenerator:
    def test_generate_template(self):
        gen = KpatchGenerator()
        verdict = Argument(
            agent_name="Test",
            claim="NULL deref in mlx5_poll_cq",
            confidence=0.8,
            evidences=["Module: mlx5_core", "Panic at mlx5_poll_cq+0x124"],
        )
        code = gen.generate(verdict)
        assert "mlx5_poll_cq" in code
        assert "klp_func" in code
        assert "klp_patch" in code
        assert "MODULE_LICENSE" in code
        assert "GPL" in code

    def test_generate_makefile(self):
        makefile = KpatchGenerator.generate_makefile()
        assert "obj-m" in makefile
        assert "modules" in makefile

    def test_extract_function(self):
        gen = KpatchGenerator()
        verdict = Argument(
            agent_name="Test", claim="x", confidence=0.5,
            evidences=["Panic at my_function+0xabc"],
        )
        func = gen._extract_function(verdict)
        assert func == "my_function"

    def test_extract_module(self):
        gen = KpatchGenerator()
        verdict = Argument(
            agent_name="Test", claim="x", confidence=0.5,
            evidences=["Module: nvme", "Panic at f+0x1"],
        )
        mod = gen._extract_module(verdict)
        assert mod == "nvme"


# ============================================================
# Validator Tests
# ============================================================

class TestValidator:
    def test_syntax_pass(self):
        code = """
#include <uapi/linux/ptrace.h>
BPF_HASH(issues, u64, u64);
int test(struct pt_regs *ctx) { return 0; }
"""
        validator = EbpfValidator()
        ok, msg = validator.validate_syntax_only(code)
        assert ok is True
        assert "passed" in msg.lower()

    def test_syntax_fail_no_bpf(self):
        code = "int main() { return 0; }"
        validator = EbpfValidator()
        ok, msg = validator.validate_syntax_only(code)
        assert ok is False
        assert "BPF" in msg

    def test_syntax_fail_unbalanced_braces(self):
        code = """
BPF_HASH(m, u64, u64);
int test(struct pt_regs *ctx) { { return 0; }
"""
        validator = EbpfValidator()
        ok, msg = validator.validate_syntax_only(code)
        assert ok is False
        assert "braces" in msg.lower()


# ============================================================
# Token Counter Tests
# ============================================================

class TestTokenCounter:
    def test_record_and_sum(self):
        counter = TokenCounter()
        counter.record(100, 50)
        counter.record(200, 100)
        assert counter.total_prompt_tokens == 300
        assert counter.total_completion_tokens == 150
        assert counter.total_tokens == 450

    def test_summary(self):
        counter = TokenCounter()
        counter.record(100, 50)
        summary = counter.summary()
        assert summary["total_tokens"] == 150


# ============================================================
# Config Tests
# ============================================================

class TestConfig:
    def test_load_default_config(self):
        config = load_config("/nonexistent/config.yaml")
        assert isinstance(config, AppConfig)
        assert config.llm.provider == "openai"
        assert config.debate.rounds == 2

    def test_load_from_env(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-123"}):
            config = load_config("/nonexistent/config.yaml")
            assert config.llm.api_key == "test-key-123"


# ============================================================
# Report Tests
# ============================================================

class TestReport:
    def test_report_to_dict(self):
        report = AnalysisReport(vmcore_path="/test", vmlinux_path="/test", hostname="host-01")
        d = report.to_dict()
        assert d["status"] == "completed"
        assert d["hostname"] == "host-01"

    def test_report_summary(self):
        report = AnalysisReport(vmcore_path="/test", vmlinux_path="/test", hostname="host-01")
        report.root_cause = "NULL deref"
        report.confidence = 0.8
        summary = report.summary()
        assert "NULL deref" in summary
        assert "0.80" in summary

    def test_report_set_failed(self):
        report = AnalysisReport(vmcore_path="/test", vmlinux_path="/test", hostname="host-01")
        report.set_failed("test error")
        assert report.status == "failed"
        assert report.error == "test error"

    def test_report_to_json(self):
        report = AnalysisReport(vmcore_path="/test", vmlinux_path="/test", hostname="host-01")
        j = report.to_json()
        parsed = json.loads(j)
        assert parsed["status"] == "completed"


# ============================================================
# Ingestion Tests
# ============================================================

class TestIngestion:
    def test_ingest_single_mock(self):
        ingestion = CrashIngestion()
        event = ingestion.ingest_single(str(MOCK_PATH), hostname="test-host")
        assert event.crash_id.startswith("crash-test-host-")
        assert event.vmcore_path == str(MOCK_PATH)

    def test_ingest_single_not_found(self):
        ingestion = CrashIngestion()
        with pytest.raises(FileNotFoundError):
            ingestion.ingest_single("/nonexistent/vmcore")

    def test_ingest_handler_called(self):
        ingestion = CrashIngestion()
        handler_calls = []
        ingestion.on_crash(lambda e: handler_calls.append(e))
        ingestion.ingest_single(str(MOCK_PATH))
        assert len(handler_calls) == 1
        assert isinstance(handler_calls[0], CrashEvent)
