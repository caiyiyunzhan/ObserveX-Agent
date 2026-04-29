from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kcrash.collector.vmcore_reader import VMCoreReader
from kcrash.collector.change_fetcher import ChangeFetcher
from kcrash.collector.hw_errors import HWErrorCollector
from kcrash.core.fingerprint import generate_fingerprint, CrashFingerprint
from kcrash.core.severity import assess_severity, SeverityAssessment
from kcrash.core.cache import AnalysisCache
from kcrash.core.report import AnalysisReport
from kcrash.reasoning.chain_panic import phase1_semantic_analysis
from kcrash.reasoning.chain_history import phase2_history_correlation
from kcrash.agents.symbol_agent import SymbolAgent
from kcrash.agents.change_agent import ChangeAgent
from kcrash.agents.hardware_agent import HardwareAgent
from kcrash.debate.moderator import DebateModerator
from kcrash.patch.generator import EbpfGenerator
from kcrash.patch.validator import EbpfValidator
from kcrash.patch.kpatch import KpatchGenerator
from kcrash.llm.client import LLMClient
from kcrash.utils.token_counter import get_token_counter
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.pipeline")


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class StageResult:
    name: str
    status: StageStatus
    duration_ms: float
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class AnalysisPipeline:
    def __init__(
        self,
        llm_client: LLMClient,
        cache: AnalysisCache | None = None,
        enable_patch: bool = True,
        patch_type: str = "ebpf",
        debate_rounds: int = 2,
        min_confidence: float = 0.6,
        hostname: str = "unknown",
        hours: int = 72,
    ) -> None:
        self._llm = llm_client
        self._cache = cache or AnalysisCache(ttl_seconds=0)
        self._enable_patch = enable_patch
        self._patch_type = patch_type
        self._debate_rounds = debate_rounds
        self._min_confidence = min_confidence
        self._hostname = hostname
        self._hours = hours
        self._stages: list[StageResult] = []

    def run(self, vmcore_path: str, vmlinux_path: str) -> AnalysisReport:
        pipeline_start = time.time()

        report = AnalysisReport(
            vmcore_path=vmcore_path,
            vmlinux_path=vmlinux_path,
            hostname=self._hostname,
        )

        # Stage 1: Read vmcore and generate fingerprint
        stage1 = self._stage_collect(vmcore_path, vmlinux_path, report)
        self._stages.append(stage1)
        if stage1.status == StageStatus.FAILED:
            report.set_failed(str(stage1.error))
            return report

        # Stage 2: Check cache
        cache_key = AnalysisCache.make_key(
            report.fingerprint.hash_value, self._llm.model
        )
        cached = self._cache.get(cache_key)
        if cached:
            logger.info("Cache hit for fingerprint %s", report.fingerprint.hash_value)
            report.merge_cached(cached)
            return report

        # Stage 3: Assess severity
        stage3 = self._stage_severity(report)
        self._stages.append(stage3)

        # Stage 4: Phase 1 semantic analysis
        stage4 = self._stage_phase1(vmcore_path, vmlinux_path, report)
        self._stages.append(stage4)

        # Stage 5: Phase 2 history correlation
        stage5 = self._stage_phase2(report)
        self._stages.append(stage5)

        # Stage 6: Multi-agent debate
        stage6 = self._stage_debate(report)
        self._stages.append(stage6)

        # Stage 7: Patch generation (if enabled)
        if self._enable_patch and report.confidence >= self._min_confidence:
            stage7 = self._stage_patch(report)
            self._stages.append(stage7)

        # Finalize
        report.total_duration_ms = (time.time() - pipeline_start) * 1000
        report.token_usage = get_token_counter().summary()
        report.pipeline_stages = [
            {"name": s.name, "status": s.status.value, "duration_ms": s.duration_ms}
            for s in self._stages
        ]

        # Cache the result
        self._cache.set(cache_key, report.to_dict())

        return report

    def _stage_collect(
        self, vmcore_path: str, vmlinux_path: str, report: AnalysisReport
    ) -> StageResult:
        start = time.time()
        name = "collect"
        try:
            reader = VMCoreReader(vmcore_path, vmlinux_path)
            frames = reader.get_panic_stack()
            dmesg = reader.read_kernel_log()

            mock_data = None
            if vmcore_path.endswith(".json"):
                with open(vmcore_path, "r") as f:
                    mock_data = json.load(f).get("metadata", {})

            report.frames = frames
            report.dmesg = dmesg
            report.mock_data = mock_data

            fingerprint = generate_fingerprint(frames, dmesg)
            report.fingerprint = fingerprint

            elapsed = (time.time() - start) * 1000
            logger.info(
                "Collected %d frames, fingerprint=%s",
                len(frames),
                fingerprint.hash_value,
                extra={"component": name},
            )
            return StageResult(
                name=name,
                status=StageStatus.COMPLETED,
                duration_ms=elapsed,
                data={"frame_count": len(frames), "fingerprint": fingerprint.hash_value},
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            logger.error("Collection failed: %s", exc)
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )

    def _stage_severity(self, report: AnalysisReport) -> StageResult:
        start = time.time()
        name = "severity"
        try:
            hw_errors = []
            if report.mock_data:
                hw_errors = report.mock_data.get("mcelog_errors", []) + \
                            report.mock_data.get("edac_errors", [])

            sibling_count = 0
            if report.mock_data:
                sibling_count = len(report.mock_data.get("sibling_crashes", []))

            assessment = assess_severity(
                report.fingerprint,
                report.frames,
                hw_errors,
                sibling_count,
            )
            report.severity = assessment

            elapsed = (time.time() - start) * 1000
            logger.info(
                "Severity: %s (score=%.1f)",
                assessment.level.label(),
                assessment.score,
            )
            return StageResult(
                name=name,
                status=StageStatus.COMPLETED,
                duration_ms=elapsed,
                data={"level": assessment.level.label(), "score": assessment.score},
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )

    def _stage_phase1(
        self, vmcore_path: str, vmlinux_path: str, report: AnalysisReport
    ) -> StageResult:
        start = time.time()
        name = "phase1_semantic"
        try:
            reader = VMCoreReader(vmcore_path, vmlinux_path)
            panic_data = phase1_semantic_analysis(
                reader, self._llm, max_tokens=4096
            )
            report.phase1_result = panic_data

            elapsed = (time.time() - start) * 1000
            logger.info(
                "Phase 1 complete: panic_point=%s",
                panic_data.get("panic_point", "N/A"),
            )
            return StageResult(
                name=name, status=StageStatus.COMPLETED, duration_ms=elapsed
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            logger.error("Phase 1 failed: %s", exc)
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )

    def _stage_phase2(self, report: AnalysisReport) -> StageResult:
        start = time.time()
        name = "phase2_correlation"
        try:
            change_fetcher = ChangeFetcher(mock_data=report.mock_data)
            hw_collector = HWErrorCollector(mock_data=report.mock_data)
            history_data = phase2_history_correlation(
                report.phase1_result,
                change_fetcher,
                hw_collector,
                self._llm,
                hostname=self._hostname,
                hours=self._hours,
            )
            report.phase2_result = history_data

            elapsed = (time.time() - start) * 1000
            logger.info("Phase 2 complete: %d candidates",
                        len(history_data.get("root_cause_candidates", [])))
            return StageResult(
                name=name, status=StageStatus.COMPLETED, duration_ms=elapsed
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            logger.error("Phase 2 failed: %s", exc)
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )

    def _stage_debate(self, report: AnalysisReport) -> StageResult:
        start = time.time()
        name = "debate"
        try:
            context = {**report.phase1_result, **report.phase2_result}
            agents = [SymbolAgent(), ChangeAgent(), HardwareAgent()]
            moderator = DebateModerator(agents, rounds=self._debate_rounds)
            result = moderator.conduct(context)

            report.debate_result = result
            report.confidence = result["final_confidence"]
            report.root_cause = result["verdict"].claim
            report.verdict_agent = result["verdict"].agent_name
            report.transcript = result["transcript"]

            elapsed = (time.time() - start) * 1000
            logger.info(
                "Debate complete: verdict=%s, confidence=%.2f, consensus=%s",
                result["verdict"].claim,
                result["final_confidence"],
                result.get("is_consensus", False),
            )
            return StageResult(
                name=name, status=StageStatus.COMPLETED, duration_ms=elapsed
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            logger.error("Debate failed: %s", exc)
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )

    def _stage_patch(self, report: AnalysisReport) -> StageResult:
        start = time.time()
        name = "patch_generation"
        try:
            verdict = report.debate_result["verdict"]

            if self._patch_type == "kpatch":
                generator = KpatchGenerator(llm_client=self._llm)
                patch_code = generator.generate(verdict)
                report.patch_type = "kpatch"
            else:
                generator = EbpfGenerator(
                    llm_client=self._llm._client,
                    model=self._llm.model,
                )
                patch_code = generator.generate(verdict)
                report.patch_type = "ebpf"

            report.patch_code = patch_code

            validator = EbpfValidator()
            valid, msg = validator.validate_syntax_only(patch_code)
            report.patch_valid = valid
            report.patch_validation_msg = msg

            elapsed = (time.time() - start) * 1000
            logger.info(
                "Patch generated: type=%s, valid=%s",
                report.patch_type,
                valid,
            )
            return StageResult(
                name=name, status=StageStatus.COMPLETED, duration_ms=elapsed
            )
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            logger.error("Patch generation failed: %s", exc)
            return StageResult(
                name=name, status=StageStatus.FAILED, duration_ms=elapsed, error=str(exc)
            )
