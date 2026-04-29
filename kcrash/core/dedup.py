from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.dedup")


@dataclass
class DedupEntry:
    fingerprint_hash: str
    first_seen: float
    last_seen: float
    count: int
    suppressed: int = 0
    hosts: set[str] = field(default_factory=set)


class CrashDeduplicator:
    def __init__(
        self,
        window_seconds: int = 300,
        max_suppressed: int = 10,
        alert_after: int = 3,
    ) -> None:
        self._window = window_seconds
        self._max_suppressed = max_suppressed
        self._alert_after = alert_after
        self._entries: dict[str, DedupEntry] = {}

    def check(self, fingerprint_hash: str, hostname: str = "") -> dict[str, Any]:
        now = time.time()
        entry = self._entries.get(fingerprint_hash)

        if entry is None:
            self._entries[fingerprint_hash] = DedupEntry(
                fingerprint_hash=fingerprint_hash,
                first_seen=now,
                last_seen=now,
                count=1,
                hosts={hostname} if hostname else set(),
            )
            return {"is_duplicate": False, "should_process": True, "count": 1}

        if now - entry.last_seen > self._window:
            entry.first_seen = now
            entry.last_seen = now
            entry.count = 1
            entry.suppressed = 0
            if hostname:
                entry.hosts.add(hostname)
            return {"is_duplicate": False, "should_process": True, "count": 1}

        entry.last_seen = now
        entry.count += 1
        if hostname:
            entry.hosts.add(hostname)

        if entry.suppressed >= self._max_suppressed:
            logger.warning(
                "Crash %s suppressed %d times, dropping",
                fingerprint_hash, entry.suppressed,
            )
            return {
                "is_duplicate": True,
                "should_process": False,
                "count": entry.count,
                "suppressed": entry.suppressed,
                "reason": "max_suppressed",
            }

        entry.suppressed += 1

        should_alert = entry.count >= self._alert_after

        return {
            "is_duplicate": True,
            "should_process": should_alert,
            "count": entry.count,
            "suppressed": entry.suppressed,
            "hosts": list(entry.hosts),
            "window_seconds": self._window,
            "alert": should_alert and entry.count == self._alert_after,
        }

    def get_cluster_alerts(self) -> list[dict[str, Any]]:
        now = time.time()
        alerts = []
        for fp, entry in self._entries.items():
            if now - entry.last_seen > self._window:
                continue
            if len(entry.hosts) >= 2:
                alerts.append({
                    "fingerprint": fp,
                    "count": entry.count,
                    "hosts": list(entry.hosts),
                    "host_count": len(entry.hosts),
                    "first_seen": entry.first_seen,
                    "last_seen": entry.last_seen,
                })
        return sorted(alerts, key=lambda a: a["host_count"], reverse=True)

    def cleanup(self) -> int:
        now = time.time()
        stale = [
            fp for fp, entry in self._entries.items()
            if now - entry.last_seen > self._window * 2
        ]
        for fp in stale:
            del self._entries[fp]
        return len(stale)

    @property
    def active_entries(self) -> int:
        now = time.time()
        return sum(
            1 for e in self._entries.values()
            if now - e.last_seen <= self._window
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_entries": self.active_entries,
            "total_entries": len(self._entries),
            "window_seconds": self._window,
            "cluster_alerts": self.get_cluster_alerts(),
        }
