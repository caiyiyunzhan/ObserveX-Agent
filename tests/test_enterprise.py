from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kcrash.exceptions import (
    KCashError,
    VMCoreNotFoundError,
    LLMError,
    LLMTimeoutError,
    LLMRateLimitError,
    LLMAuthError,
    LLMResponseParseError,
    AnalysisError,
    PatchGenerationError,
    PatchValidationError,
    CacheError,
    ConfigError,
    ConfigMissingError,
    NotificationError,
    DatabaseError,
    AuthenticationError,
    RateLimitExceededError,
)
from kcrash.core.database import Database, CrashRecord
from kcrash.core.circuit_breaker import CircuitBreaker, CircuitState
from kcrash.core.metrics import MetricsCollector, Counter, Gauge, Histogram, Summary
from kcrash.core.dedup import CrashDeduplicator
from kcrash.api.auth import APIKeyStore
from kcrash.core.batch import BatchProcessor
from kcrash.notifications.manager import LogChannel, ConsoleChannel, NotificationManager
from kcrash.core.severity import Severity


# ============================================================
# Exception Tests
# ============================================================

class TestExceptions:
    def test_base_exception_to_dict(self):
        exc = KCashError("test error", code="TEST", details={"key": "val"})
        d = exc.to_dict()
        assert d["error"] == "TEST"
        assert d["message"] == "test error"
        assert d["details"]["key"] == "val"

    def test_vmcore_not_found(self):
        exc = VMCoreNotFoundError("file missing", vmcore_path="/tmp/x")
        assert "file missing" in str(exc)
        assert exc.details["vmcore_path"] == "/tmp/x"

    def test_llm_error_with_retry(self):
        exc = LLMError("timeout", model="gpt-4", retry_count=3)
        assert exc.details["retry_count"] == 3
        assert exc.details["model"] == "gpt-4"

    def test_llm_timeout_inherits_llm_error(self):
        exc = LLMTimeoutError("timed out")
        assert isinstance(exc, LLMError)
        assert isinstance(exc, KCashError)

    def test_llm_rate_limit(self):
        exc = LLMRateLimitError("rate limited")
        assert isinstance(exc, LLMError)

    def test_llm_auth_error(self):
        exc = LLMAuthError("bad key")
        assert isinstance(exc, LLMError)

    def test_llm_parse_error(self):
        exc = LLMResponseParseError("invalid json")
        assert isinstance(exc, LLMError)

    def test_analysis_error_with_stage(self):
        exc = AnalysisError("failed", stage="phase1", crash_id="c1")
        assert exc.details["stage"] == "phase1"
        assert exc.details["crash_id"] == "c1"

    def test_patch_generation_error(self):
        exc = PatchGenerationError("template not found")
        assert isinstance(exc, PatchValidationError.__bases__[0])

    def test_config_missing(self):
        exc = ConfigMissingError("api_key required")
        assert isinstance(exc, ConfigError)

    def test_database_error(self):
        exc = DatabaseError("connection failed")
        assert isinstance(exc, KCashError)

    def test_authentication_error(self):
        exc = AuthenticationError("invalid key")
        assert isinstance(exc, KCashError)

    def test_rate_limit_exceeded(self):
        exc = RateLimitExceededError(retry_after=30)
        assert exc.retry_after == 30
        assert exc.details["retry_after"] == 30

    def test_notification_error(self):
        exc = NotificationError("webhook failed")
        assert isinstance(exc, KCashError)


# ============================================================
# Database Tests
# ============================================================

class TestDatabase:
    def _make_db(self):
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        return Database(db_path=path), path

    def _cleanup(self, db, path):
        db.close()
        os.unlink(path)

    def test_init_creates_schema(self):
        db, path = self._make_db()
        try:
            conn = db._get_conn()
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = {t["name"] for t in tables}
            assert "crash_history" in table_names
            assert "crash_events" in table_names
            assert "notification_log" in table_names
            assert "schema_version" in table_names
        finally:
            self._cleanup(db, path)

    def test_save_and_get_crash(self):
        db, path = self._make_db()
        try:
            db.save_crash({
                "id": "test-1",
                "fingerprint_hash": "abc123",
                "hostname": "host-01",
                "vmcore_path": "/tmp/vmcore",
                "root_cause": "NULL deref",
                "confidence": 0.85,
                "severity_level": "HIGH",
                "severity_score": 75.0,
                "verdict_agent": "SymbolAgent",
                "patch_type": "ebpf",
                "patch_valid": True,
                "status": "completed",
                "duration_ms": 5000.0,
                "token_total": 3000,
                "created_at": "2024-01-15T10:00:00Z",
            })

            record = db.get_crash("test-1")
            assert record is not None
            assert record.root_cause == "NULL deref"
            assert record.confidence == 0.85
            assert record.severity_level == "HIGH"
            assert record.patch_valid is True
        finally:
            self._cleanup(db, path)

    def test_get_crashes_by_fingerprint(self):
        db, path = self._make_db()
        try:
            for i in range(3):
                db.save_crash({
                    "id": f"test-{i}",
                    "fingerprint_hash": "abc123",
                    "hostname": f"host-{i}",
                    "vmcore_path": f"/tmp/vmcore-{i}",
                    "created_at": f"2024-01-{15+i}T10:00:00Z",
                })

            records = db.get_crashes_by_fingerprint("abc123")
            assert len(records) == 3
        finally:
            self._cleanup(db, path)

    def test_get_crashes_by_hostname(self):
        db, path = self._make_db()
        try:
            db.save_crash({
                "id": "test-1", "fingerprint_hash": "abc", "hostname": "host-01",
                "vmcore_path": "/tmp/v",
            })
            db.save_crash({
                "id": "test-2", "fingerprint_hash": "def", "hostname": "host-02",
                "vmcore_path": "/tmp/v",
            })

            records = db.get_crashes_by_hostname("host-01")
            assert len(records) == 1
            assert records[0].hostname == "host-01"
        finally:
            self._cleanup(db, path)

    def test_get_crash_count(self):
        db, path = self._make_db()
        try:
            assert db.get_crash_count() == 0
            db.save_crash({
                "id": "t1", "fingerprint_hash": "a", "hostname": "h", "vmcore_path": "/v",
            })
            assert db.get_crash_count() == 1
        finally:
            self._cleanup(db, path)

    def test_get_crash_not_found(self):
        db, path = self._make_db()
        try:
            assert db.get_crash("nonexistent") is None
        finally:
            self._cleanup(db, path)

    def test_log_event(self):
        db, path = self._make_db()
        try:
            db.save_crash({
                "id": "t1", "fingerprint_hash": "a", "hostname": "h", "vmcore_path": "/v",
            })
            db.log_event("t1", "analysis_complete", {"confidence": 0.8})
            conn = db._get_conn()
            row = conn.execute("SELECT * FROM crash_events WHERE crash_id='t1'").fetchone()
            assert row is not None
            assert row["event_type"] == "analysis_complete"
        finally:
            self._cleanup(db, path)

    def test_log_notification(self):
        db, path = self._make_db()
        try:
            db.log_notification("t1", "webhook", "http://x", "sent")
            conn = db._get_conn()
            row = conn.execute("SELECT * FROM notification_log WHERE crash_id='t1'").fetchone()
            assert row is not None
            assert row["channel"] == "webhook"
        finally:
            self._cleanup(db, path)

    def test_purge_old(self):
        db, path = self._make_db()
        try:
            db.save_crash({
                "id": "old-1", "fingerprint_hash": "a", "hostname": "h",
                "vmcore_path": "/v", "created_at": "2020-01-01T00:00:00Z",
            })
            deleted = db.purge_old(days=0)
            assert deleted >= 1
        finally:
            self._cleanup(db, path)

    def test_transaction_rollback(self):
        db, path = self._make_db()
        try:
            with pytest.raises(Exception):
                with db.transaction() as conn:
                    conn.execute("INSERT INTO crash_history (id) VALUES ('x')")
                    raise ValueError("simulated error")
            assert db.get_crash("x") is None
        finally:
            self._cleanup(db, path)


# ============================================================
# CircuitBreaker Tests
# ============================================================

class TestCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(name="test")
        assert cb.state == CircuitState.CLOSED

    def test_successful_call(self):
        cb = CircuitBreaker()
        result = cb.call(lambda: 42)
        assert result == 42
        assert cb.stats.successful_calls == 1

    def test_failed_call_stays_closed(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == CircuitState.CLOSED
        assert cb.stats.failed_calls == 2

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == CircuitState.OPEN

    def test_rejects_when_open(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=999)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        with pytest.raises(LLMError, match="OPEN"):
            cb.call(lambda: 42)
        assert cb.stats.rejected_calls == 1

    def test_half_open_after_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_succeeds_closes(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05, half_open_max_calls=2)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        time.sleep(0.1)
        result = cb.call(lambda: "recovered")
        assert result == "recovered"
        assert cb.state == CircuitState.CLOSED

    def test_reset(self):
        cb = CircuitBreaker(failure_threshold=2)
        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(lambda: (_ for _ in ()).throw(ValueError("fail")))
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_to_dict(self):
        cb = CircuitBreaker(name="mybreaker")
        d = cb.to_dict()
        assert d["name"] == "mybreaker"
        assert d["state"] == "closed"


# ============================================================
# Metrics Tests
# ============================================================

class TestMetrics:
    def test_counter(self):
        mc = MetricsCollector()
        c = mc.counter("test_counter")
        c.inc()
        c.inc(5)
        assert c.value == 6

    def test_counter_with_labels(self):
        mc = MetricsCollector()
        c1 = mc.counter("req", {"method": "GET"})
        c2 = mc.counter("req", {"method": "POST"})
        c1.inc()
        c2.inc(3)
        assert c1.value == 1
        assert c2.value == 3

    def test_gauge(self):
        mc = MetricsCollector()
        g = mc.gauge("test_gauge")
        g.set(10)
        g.inc(5)
        g.dec(3)
        assert g.value == 12

    def test_histogram(self):
        mc = MetricsCollector()
        h = mc.histogram("test_hist")
        h.observe(100)
        h.observe(500)
        h.observe(5000)
        assert h.total_count == 3
        assert h.total_sum == 5600
        assert h.avg == pytest.approx(1866.67, rel=0.01)

    def test_summary(self):
        mc = MetricsCollector()
        s = mc.summary("test_summary")
        for v in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
            s.observe(v)
        assert s.percentile(50) >= 50
        assert s.percentile(90) >= 80
        assert s.avg == 55.0
        assert len(s.values) == 10

    def test_export(self):
        mc = MetricsCollector()
        mc.counter("c1").inc(10)
        mc.gauge("g1").set(42)
        mc.histogram("h1").observe(100)
        data = mc.export()
        assert "counters" in data
        assert "gauges" in data
        assert "histograms" in data
        assert data["counters"]["c1"] == 10
        assert data["gauges"]["g1"] == 42

    def test_reset(self):
        mc = MetricsCollector()
        mc.counter("c1").inc(10)
        mc.reset()
        data = mc.export()
        assert data["counters"] == {}

    def test_global_metrics(self):
        from kcrash.core.metrics import get_metrics
        m = get_metrics()
        assert isinstance(m, MetricsCollector)


# ============================================================
# Deduplication Tests
# ============================================================

class TestDedup:
    def test_first_crash_not_duplicate(self):
        dedup = CrashDeduplicator(window_seconds=300)
        result = dedup.check("fp-001", "host-01")
        assert result["is_duplicate"] is False
        assert result["should_process"] is True
        assert result["count"] == 1

    def test_second_crash_is_duplicate(self):
        dedup = CrashDeduplicator(window_seconds=300, alert_after=10)
        dedup.check("fp-001", "host-01")
        result = dedup.check("fp-001", "host-01")
        assert result["is_duplicate"] is True
        assert result["count"] == 2

    def test_suppress_after_max(self):
        dedup = CrashDeduplicator(window_seconds=300, max_suppressed=3, alert_after=10)
        for _ in range(5):
            dedup.check("fp-001", "host-01")
        result = dedup.check("fp-001", "host-01")
        assert result["should_process"] is False
        assert result.get("reason") == "max_suppressed"

    def test_cluster_detection(self):
        dedup = CrashDeduplicator(window_seconds=300, alert_after=2)
        dedup.check("fp-001", "host-01")
        dedup.check("fp-001", "host-02")
        alerts = dedup.get_cluster_alerts()
        assert len(alerts) == 1
        assert alerts[0]["host_count"] == 2

    def test_cleanup(self):
        dedup = CrashDeduplicator(window_seconds=1)
        dedup.check("fp-001", "host-01")
        time.sleep(0.1)
        cleaned = dedup.cleanup()
        assert cleaned >= 0

    def test_active_entries(self):
        dedup = CrashDeduplicator(window_seconds=300)
        dedup.check("fp-001")
        dedup.check("fp-002")
        assert dedup.active_entries == 2

    def test_to_dict(self):
        dedup = CrashDeduplicator()
        dedup.check("fp-001")
        d = dedup.to_dict()
        assert d["active_entries"] == 1
        assert "cluster_alerts" in d


# ============================================================
# API Key Store Tests
# ============================================================

class TestAPIKeyStore:
    def test_register_and_authenticate(self):
        store = APIKeyStore()
        raw_key, api_key = store.register_key("test-app", scopes=["analyze"])
        assert raw_key.startswith("kcrash-")
        authenticated = store.authenticate(raw_key)
        assert authenticated.key_id == api_key.key_id

    def test_invalid_key_rejected(self):
        store = APIKeyStore()
        with pytest.raises(AuthenticationError, match="Invalid"):
            store.authenticate("invalid-key")

    def test_disabled_key_rejected(self):
        store = APIKeyStore()
        raw_key, api_key = store.register_key("test")
        store.disable_key(api_key.key_id)
        with pytest.raises(AuthenticationError, match="disabled"):
            store.authenticate(raw_key)

    def test_expired_key_rejected(self):
        store = APIKeyStore()
        raw_key, api_key = store.register_key("test", ttl_days=-1)
        with pytest.raises(AuthenticationError, match="expired"):
            store.authenticate(raw_key)

    def test_scope_check(self):
        store = APIKeyStore()
        raw_key, api_key = store.register_key("test", scopes=["read"])
        with pytest.raises(AuthenticationError, match="scope"):
            store.check_scope(api_key, "write")

    def test_scope_wildcard(self):
        store = APIKeyStore()
        _, api_key = store.register_key("admin", scopes=["*"])
        store.check_scope(api_key, "anything")

    def test_rate_limit(self):
        store = APIKeyStore()
        _, api_key = store.register_key("test", rate_limit=2)
        store.check_rate_limit(api_key.key_id)
        store.check_rate_limit(api_key.key_id)
        with pytest.raises(RateLimitExceededError):
            store.check_rate_limit(api_key.key_id)

    def test_list_keys(self):
        store = APIKeyStore()
        store.register_key("app1")
        store.register_key("app2")
        keys = store.list_keys()
        assert len(keys) == 2
        assert all("key_id" in k for k in keys)

    def test_generate_key_unique(self):
        k1, h1 = APIKeyStore.generate_key()
        k2, h2 = APIKeyStore.generate_key()
        assert k1 != k2
        assert h1 != h2


# ============================================================
# Notification Tests
# ============================================================

class TestNotifications:
    def test_log_channel_send(self):
        channel = LogChannel()
        assert channel.send("test", "body") is True
        assert channel.health_check() is True

    def test_console_channel_send(self):
        channel = ConsoleChannel()
        assert channel.send("test", "body", {"severity": "CRITICAL"}) is True

    def test_manager_notify(self):
        manager = NotificationManager()
        manager.add_channel(ConsoleChannel())
        results = manager.notify(
            crash_id="c1",
            root_cause="NULL deref",
            severity=Severity.CRITICAL,
            confidence=0.9,
        )
        assert len(results) == 1
        assert results[0].success is True

    def test_manager_health_check(self):
        manager = NotificationManager()
        manager.add_channel(LogChannel())
        health = manager.health_check()
        assert health["log"] is True

    def test_manager_no_channels(self):
        manager = NotificationManager()
        results = manager.notify(
            crash_id="c1", root_cause="x",
            severity=Severity.LOW, confidence=0.5,
        )
        assert results == []


# ============================================================
# Batch Processor Tests
# ============================================================

class TestBatchProcessor:
    def test_process_empty_batch(self):
        llm_mock = MagicMock()
        config_mock = MagicMock()
        config_mock.patch.enable_generation = False
        config_mock.patch.default_type = "ebpf"
        config_mock.debate.rounds = 2
        config_mock.debate.min_consensus_ratio = 0.6
        processor = BatchProcessor(llm_client=llm_mock, config=config_mock)
        result = processor.process_batch([])
        assert result.total == 0
        assert result.completed == 0


# ============================================================
# Config Tests
# ============================================================

class TestConfigEnhanced:
    def test_all_config_sections_exist(self):
        from kcrash.utils.config import AppConfig
        config = AppConfig()
        assert config.llm.provider == "openai"
        assert config.cache.enabled is True
        assert config.database.enabled is True
        assert config.dedup.enabled is True
        assert config.circuit_breaker.enabled is True
        assert config.metrics.enabled is True
        assert config.api.host == "0.0.0.0"
        assert config.api.port == 8080

    def test_env_var_resolution(self):
        with patch.dict(os.environ, {"MY_KEY": "secret123"}):
            from kcrash.utils.config import LLMConfig
            config = LLMConfig(api_key="${MY_KEY}")
            assert config.api_key == "secret123"

    def test_deep_env_resolution(self):
        from kcrash.utils.config import _resolve_deep
        with patch.dict(os.environ, {"TEST": "value"}):
            result = _resolve_deep({"a": {"b": "${TEST}"}})
            assert result["a"]["b"] == "value"
