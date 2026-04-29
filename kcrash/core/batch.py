from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from kcrash.core.pipeline import AnalysisPipeline
from kcrash.core.report import AnalysisReport
from kcrash.core.database import Database
from kcrash.core.dedup import CrashDeduplicator
from kcrash.core.metrics import get_metrics
from kcrash.llm.client import LLMClient
from kcrash.utils.logging import get_logger
from kcrash.utils.config import AppConfig

logger = get_logger("kcrash.batch")


@dataclass
class BatchJob:
    job_id: str
    vmcore_path: str
    vmlinux_path: str
    hostname: str
    status: str = "pending"
    result: dict[str, Any] | None = None
    error: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0


@dataclass
class BatchResult:
    batch_id: str
    total: int
    completed: int
    failed: int
    skipped: int
    duration_ms: float
    results: list[dict[str, Any]] = field(default_factory=list)


class BatchProcessor:
    def __init__(
        self,
        llm_client: LLMClient,
        config: AppConfig,
        db: Database | None = None,
        dedup: CrashDeduplicator | None = None,
        max_workers: int = 4,
    ) -> None:
        self._llm = llm_client
        self._config = config
        self._db = db
        self._dedup = dedup
        self._max_workers = max_workers
        self._metrics = get_metrics()

    def process_batch(
        self,
        items: list[dict[str, str]],
        batch_id: str | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> BatchResult:
        batch_id = batch_id or f"batch-{int(time.time())}"
        start = time.time()
        total = len(items)
        completed = 0
        failed = 0
        skipped = 0
        results: list[dict[str, Any]] = []

        jobs = [
            BatchJob(
                job_id=f"{batch_id}-{i}",
                vmcore_path=item.get("vmcore", ""),
                vmlinux_path=item.get("vmlinux", "dummy"),
                hostname=item.get("hostname", "unknown"),
            )
            for i, item in enumerate(items)
        ]

        with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            future_to_job = {
                executor.submit(self._process_single, job): job
                for job in jobs
            }

            for future in as_completed(future_to_job):
                job = future_to_job[future]
                try:
                    result = future.result()
                    if result.get("status") == "skipped":
                        skipped += 1
                    else:
                        completed += 1
                    results.append(result)
                except Exception as exc:
                    failed += 1
                    logger.error("Job %s failed: %s", job.job_id, exc)
                    results.append({
                        "job_id": job.job_id,
                        "vmcore": job.vmcore_path,
                        "status": "failed",
                        "error": str(exc),
                    })

                if on_progress:
                    on_progress(completed + failed + skipped, total)

        elapsed = (time.time() - start) * 1000

        self._metrics.counter("kcrash_batch_total").inc()
        self._metrics.counter("kcrash_batch_items_completed").inc(completed)
        self._metrics.counter("kcrash_batch_items_failed").inc(failed)
        self._metrics.counter("kcrash_batch_items_skipped").inc(skipped)
        self._metrics.histogram("kcrash_batch_duration_ms").observe(elapsed)

        return BatchResult(
            batch_id=batch_id,
            total=total,
            completed=completed,
            failed=failed,
            skipped=skipped,
            duration_ms=elapsed,
            results=results,
        )

    def _process_single(self, job: BatchJob) -> dict[str, Any]:
        job.started_at = time.time()
        job.status = "running"

        try:
            pipeline = AnalysisPipeline(
                llm_client=self._llm,
                enable_patch=self._config.patch.enable_generation,
                patch_type=self._config.patch.default_type,
                debate_rounds=self._config.debate.rounds,
                min_confidence=self._config.debate.min_consensus_ratio,
                hostname=job.hostname,
            )

            report = pipeline.run(job.vmcore_path, job.vmlinux_path)

            if self._dedup and report.fingerprint:
                dedup_result = self._dedup.check(
                    report.fingerprint.hash_value, job.hostname
                )
                if dedup_result.get("status") == "suppressed":
                    job.status = "skipped"
                    return {"job_id": job.job_id, "status": "skipped", "reason": "dedup"}

            if self._db and report.fingerprint:
                severity = report.severity
                self._db.save_crash({
                    "id": job.job_id,
                    "fingerprint_hash": report.fingerprint.hash_value,
                    "hostname": job.hostname,
                    "vmcore_path": job.vmcore_path,
                    "root_cause": report.root_cause,
                    "confidence": report.confidence,
                    "severity_level": severity.level.label() if severity else "UNKNOWN",
                    "severity_score": severity.score if severity else 0,
                    "verdict_agent": report.verdict_agent,
                    "patch_type": report.patch_type,
                    "patch_valid": report.patch_valid,
                    "status": report.status,
                    "duration_ms": report.total_duration_ms,
                    "token_total": report.token_usage.get("total_tokens", 0),
                    "created_at": report.timestamp,
                    "report": report.to_dict(),
                })

            job.status = "completed"
            job.finished_at = time.time()

            return {
                "job_id": job.job_id,
                "vmcore": job.vmcore_path,
                "hostname": job.hostname,
                "status": report.status,
                "root_cause": report.root_cause,
                "confidence": report.confidence,
                "severity": report.severity.level.label() if report.severity else "UNKNOWN",
                "duration_ms": report.total_duration_ms,
            }

        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = time.time()
            raise

    def process_manifest(self, manifest_path: str, **kwargs) -> BatchResult:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
        items = manifest.get("crashes", [])
        return self.process_batch(items, **kwargs)
