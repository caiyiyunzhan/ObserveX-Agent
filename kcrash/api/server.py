from __future__ import annotations

import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from kcrash.core.pipeline import AnalysisPipeline
from kcrash.core.cache import AnalysisCache
from kcrash.core.database import Database
from kcrash.core.dedup import CrashDeduplicator
from kcrash.core.metrics import get_metrics
from kcrash.core.batch import BatchProcessor
from kcrash.core.ingestion import CrashIngestion
from kcrash.core.severity import Severity
from kcrash.llm.client import LLMClient
from kcrash.api.auth import APIKeyStore
from kcrash.utils.config import load_config
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.api")

_cache: AnalysisCache | None = None
_llm: LLMClient | None = None
_db: Database | None = None
_dedup: CrashDeduplicator | None = None
_key_store: APIKeyStore | None = None
_metrics = get_metrics()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _cache, _llm, _db, _dedup, _key_store
    config = load_config()

    if config.cache.enabled:
        _cache = AnalysisCache(
            cache_dir=config.cache.dir,
            ttl_seconds=config.cache.ttl_seconds,
            max_entries=config.cache.max_entries,
        )

    if config.database.enabled:
        _db = Database(db_path=config.database.path)

    if config.dedup.enabled:
        _dedup = CrashDeduplicator(
            window_seconds=config.dedup.window_seconds,
            max_suppressed=config.dedup.max_suppressed,
            alert_after=config.dedup.alert_after,
        )

    if config.llm.api_key:
        _llm = LLMClient(
            api_key=config.llm.api_key,
            model=config.llm.model,
            base_url=config.llm.base_url,
            max_retries=config.llm.max_retries,
            timeout=config.llm.timeout,
            rate_limit_rpm=config.llm.rate_limit_rpm,
        )

    _key_store = APIKeyStore()
    if config.api.auth_enabled:
        for key_info in config.api.api_keys:
            _key_store.register_key(
                name=key_info.get("name", "unnamed"),
                scopes=key_info.get("scopes", ["analyze"]),
                rate_limit=key_info.get("rate_limit", 100),
            )

    logger.info("API server started")
    yield

    if _db:
        _db.close()
    logger.info("API server shutting down")


app = FastAPI(
    title="kcrash-agent API",
    description="Kernel crash analysis and hot-patch generation service",
    version="0.1.0",
    lifespan=lifespan,
)


async def verify_api_key(authorization: str | None = Header(None)):
    config = load_config()
    if not config.api.auth_enabled:
        return None

    if _key_store is None:
        return None

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    raw_key = authorization[7:]
    try:
        api_key = _key_store.authenticate(raw_key)
        _key_store.check_rate_limit(api_key.key_id)
        return api_key
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))


class AnalyzeRequest(BaseModel):
    vmcore_path: str = Field(..., description="Path to vmcore dump or mock JSON")
    vmlinux_path: str = Field(..., description="Path to vmlinux with debug symbols")
    hostname: str = Field(default="unknown")
    enable_patch: bool = Field(default=False)
    patch_type: str = Field(default="ebpf", pattern="^(ebpf|kpatch)$")
    debate_rounds: int = Field(default=2, ge=1, le=5)
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    hours: int = Field(default=72, ge=1)


class BatchAnalyzeRequest(BaseModel):
    vmcores: list[str] = Field(..., description="List of vmcore paths")
    vmlinux_path: str = Field(..., description="Path to vmlinux")
    hostname: str = Field(default="unknown")
    enable_patch: bool = Field(default=False)
    max_workers: int = Field(default=4, ge=1, le=16)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "timestamp": time.time(),
        "components": {
            "cache": _cache is not None,
            "database": _db is not None,
            "llm": _llm is not None,
            "dedup": _dedup is not None,
        },
        "cache_entries": _cache.stats["entries"] if _cache else 0,
    }


@app.get("/metrics")
async def metrics():
    return _metrics.export()


@app.post("/analyze")
async def analyze_crash(
    request: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    api_key=Depends(verify_api_key),
):
    if _llm is None:
        raise HTTPException(status_code=503, detail="LLM client not configured")

    _metrics.counter("kcrash_api_analyze_requests").inc()

    try:
        pipeline = AnalysisPipeline(
            llm_client=_llm,
            cache=_cache,
            enable_patch=request.enable_patch,
            patch_type=request.patch_type,
            debate_rounds=request.debate_rounds,
            min_confidence=request.min_confidence,
            hostname=request.hostname,
            hours=request.hours,
        )

        report = pipeline.run(request.vmcore_path, request.vmlinux_path)

        if _db and report.fingerprint:
            _db.save_crash({
                "id": f"api-{int(time.time())}",
                "fingerprint_hash": report.fingerprint.hash_value,
                "hostname": request.hostname,
                "vmcore_path": request.vmcore_path,
                "root_cause": report.root_cause,
                "confidence": report.confidence,
                "severity_level": report.severity.level.label() if report.severity else "UNKNOWN",
                "severity_score": report.severity.score if report.severity else 0,
                "verdict_agent": report.verdict_agent,
                "patch_type": report.patch_type,
                "patch_valid": report.patch_valid,
                "status": report.status,
                "duration_ms": report.total_duration_ms,
                "token_total": report.token_usage.get("total_tokens", 0),
                "created_at": report.timestamp,
                "report": report.to_dict(),
            })

        severity_dict = None
        if report.severity:
            severity_dict = {
                "level": report.severity.level.label(),
                "score": report.severity.score,
                "sla_impact": report.severity.sla_impact,
                "recommended_action": report.severity.recommended_action,
            }

        patch_dict = None
        if report.patch_code:
            patch_dict = {
                "type": report.patch_type,
                "code": report.patch_code,
                "valid": report.patch_valid,
            }

        _metrics.counter("kcrash_api_analyze_success").inc()
        _metrics.histogram("kcrash_api_analyze_duration_ms").observe(report.total_duration_ms)

        return {
            "status": report.status,
            "root_cause": report.root_cause,
            "confidence": report.confidence,
            "verdict_agent": report.verdict_agent,
            "severity": severity_dict,
            "patch": patch_dict,
            "token_usage": report.token_usage,
            "total_duration_ms": report.total_duration_ms,
            "pipeline_stages": report.pipeline_stages,
        }

    except Exception as exc:
        _metrics.counter("kcrash_api_analyze_errors").inc()
        logger.error("Analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/analyze/batch")
async def analyze_batch(request: BatchAnalyzeRequest, api_key=Depends(verify_api_key)):
    if _llm is None:
        raise HTTPException(status_code=503, detail="LLM client not configured")

    config = load_config()
    processor = BatchProcessor(
        llm_client=_llm,
        config=config,
        db=_db,
        dedup=_dedup,
        max_workers=request.max_workers,
    )

    items = [
        {"vmcore": vc, "vmlinux": request.vmlinux_path, "hostname": request.hostname}
        for vc in request.vmcores
    ]

    result = processor.process_batch(items)

    return {
        "batch_id": result.batch_id,
        "total": result.total,
        "completed": result.completed,
        "failed": result.failed,
        "skipped": result.skipped,
        "duration_ms": result.duration_ms,
        "results": result.results,
    }


@app.get("/crashes/{fingerprint_hash}")
async def get_crash(fingerprint_hash: str, api_key=Depends(verify_api_key)):
    cache = _cache or AnalysisCache()
    key = AnalysisCache.make_key(fingerprint_hash)
    cached = cache.get(key)
    if cached is None:
        raise HTTPException(status_code=404, detail="Crash not found in cache")
    return cached


@app.get("/crashes")
async def list_crashes(
    hostname: str | None = None,
    hours: int = 24,
    limit: int = 100,
    api_key=Depends(verify_api_key),
):
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not available")

    if hostname:
        records = _db.get_crashes_by_hostname(hostname, limit=limit)
    else:
        records = _db.get_recent_crashes(hours=hours, limit=limit)

    return {
        "total": len(records),
        "crashes": [
            {
                "id": r.id,
                "fingerprint": r.fingerprint_hash,
                "hostname": r.hostname,
                "root_cause": r.root_cause,
                "confidence": r.confidence,
                "severity": r.severity_level,
                "status": r.status,
                "created_at": r.created_at,
            }
            for r in records
        ],
    }


@app.get("/trends")
async def get_trends(days: int = 30, min_count: int = 2, api_key=Depends(verify_api_key)):
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not available")

    trends = _db.get_trends(days=days, min_count=min_count)

    return {
        "period_days": days,
        "total_trends": len(trends),
        "trends": [
            {
                "fingerprint": t.fingerprint_hash,
                "top_function": t.top_function,
                "error_class": t.error_class,
                "count": t.occurrence_count,
                "affected_hosts": t.affected_hosts,
                "avg_confidence": round(t.avg_confidence, 3),
                "first_seen": t.first_seen,
                "last_seen": t.last_seen,
            }
            for t in trends
        ],
    }


@app.get("/dedup")
async def get_dedup_status(api_key=Depends(verify_api_key)):
    if _dedup is None:
        return {"enabled": False}
    return _dedup.to_dict()


@app.get("/stats")
async def stats(api_key=Depends(verify_api_key)):
    result: dict[str, Any] = {
        "cache": _cache.stats if _cache else {"entries": 0, "total_hits": 0},
        "metrics": _metrics.export(),
        "llm_model": _llm.model if _llm else None,
    }
    if _db:
        result["database"] = {"total_crashes": _db.get_crash_count()}
    if _dedup:
        result["dedup"] = _dedup.to_dict()
    return result


@app.delete("/cache")
async def clear_cache(api_key=Depends(verify_api_key)):
    if _cache:
        _cache.clear()
    return {"status": "cache cleared"}


@app.delete("/crashes/purge")
async def purge_old_crashes(days: int = 90, api_key=Depends(verify_api_key)):
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    deleted = _db.purge_old(days=days)
    return {"deleted": deleted, "older_than_days": days}
