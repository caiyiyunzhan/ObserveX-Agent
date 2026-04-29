from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class LLMConfig(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4-turbo"
    api_key: str = ""
    base_url: str | None = None
    max_tokens_per_call: int = 16384
    timeout: float = 120.0
    max_retries: int = 3
    retry_delay: float = 2.0
    rate_limit_rpm: int = 60

    @field_validator("api_key", mode="before")
    @classmethod
    def resolve_api_key(cls, v: str) -> str:
        if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
            return os.environ.get(v[2:-1], "")
        return v


class DebateConfig(BaseModel):
    rounds: int = 2
    min_consensus_ratio: float = 0.67


class PatchConfig(BaseModel):
    enable_generation: bool = True
    default_type: str = "ebpf"
    kernel_source_dir: str = "/usr/src/kernels/$(uname -r)"


class CacheConfig(BaseModel):
    enabled: bool = True
    dir: str = ".kcrash_cache"
    ttl_seconds: int = 3600
    max_entries: int = 1000


class DatabaseConfig(BaseModel):
    enabled: bool = True
    path: str = "kcrash.db"
    purge_after_days: int = 90


class NotificationConfig(BaseModel):
    enabled: bool = False
    webhook_url: str = ""
    min_severity: str = "HIGH"
    channels: list[str] = Field(default_factory=lambda: ["log"])


class APIConfig(BaseModel):
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    auth_enabled: bool = False
    api_keys: list[dict[str, Any]] = Field(default_factory=list)


class DedupConfig(BaseModel):
    enabled: bool = True
    window_seconds: int = 300
    max_suppressed: int = 10
    alert_after: int = 3


class CircuitBreakerConfig(BaseModel):
    enabled: bool = True
    failure_threshold: int = 5
    recovery_timeout: float = 60.0


class MetricsConfig(BaseModel):
    enabled: bool = True


class AppConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    debate: DebateConfig = Field(default_factory=DebateConfig)
    patch: PatchConfig = Field(default_factory=PatchConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    notification: NotificationConfig = Field(default_factory=NotificationConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    dedup: DedupConfig = Field(default_factory=DedupConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)


def _resolve_deep(obj: Any) -> Any:
    if isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
        return os.environ.get(obj[2:-1], obj)
    if isinstance(obj, dict):
        return {k: _resolve_deep(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_deep(v) for v in obj]
    return obj


def load_config(config_path: str | None = None) -> AppConfig:
    config_file = Path(config_path) if config_path else Path("config.yaml")

    if config_file.exists():
        with open(config_file, "r") as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    raw = _resolve_deep(raw)

    if "OPENAI_API_KEY" in os.environ and not raw.get("llm", {}).get("api_key"):
        raw.setdefault("llm", {})["api_key"] = os.environ["OPENAI_API_KEY"]

    return AppConfig(**raw)


def load_config_dict(config_path: str | None = None) -> dict[str, Any]:
    config = load_config(config_path)
    return json.loads(config.model_dump_json())
