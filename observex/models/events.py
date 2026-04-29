from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    FATAL = "fatal"


class EventSource(str, Enum):
    KERNEL = "kernel"
    APPLICATION = "application"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"
    NETWORK = "network"
    STORAGE = "storage"
    CHANGE = "change"
    EBP = "ebpf"


class ChangeType(str, Enum):
    CODE_DEPLOY = "code_deploy"
    CONFIG_CHANGE = "config_change"
    KERNEL_UPDATE = "kernel_update"
    DRIVER_UPDATE = "driver_update"
    INFRA_CHANGE = "infra_change"
    ROLLBACK = "rollback"
    CAPACITY_CHANGE = "capacity_change"


@dataclass
class RawEvent:
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)
    source: EventSource = EventSource.KERNEL
    host: str = ""
    service: str = ""
    severity: EventSeverity = EventSeverity.INFO
    message: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""
    span_id: str = ""
    raw_line: str = ""

    def fingerprint(self) -> str:
        key = f"{self.source.value}:{self.service}:{self.severity.value}:{self._normalize_msg()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _normalize_msg(self) -> str:
        import re
        msg = self.message[:200]
        msg = re.sub(r"\d{10,}", "N", msg)
        msg = re.sub(r"0x[0-9a-fA-F]+", "ADDR", msg)
        msg = re.sub(r"\d+\.\d+\.\d+\.\d+", "IP", msg)
        return msg


@dataclass
class ClusteredEvent:
    cluster_id: str = ""
    template: str = ""
    representative: RawEvent | None = None
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    hosts: set[str] = field(default_factory=set)
    sources: set[EventSource] = field(default_factory=set)
    severity: EventSeverity = EventSeverity.INFO
    member_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "template": self.template,
            "count": self.count,
            "hosts": list(self.hosts),
            "sources": [s.value for s in self.sources],
            "severity": self.severity.value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class CrossSourceCorrelation:
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    event_a: ClusteredEvent | None = None
    event_b: ClusteredEvent | None = None
    time_delta_ms: float = 0.0
    is_same_host: bool = False
    is_causally_linked: bool = False
    confidence: float = 0.0
    reasoning: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class ChangeEvent:
    change_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    change_type: ChangeType = ChangeType.CODE_DEPLOY
    target_host: str = ""
    target_service: str = ""
    description: str = ""
    operator: str = ""
    old_value: str = ""
    new_value: str = ""
    source_system: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
