from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from observex.models.events import RawEvent, ClusteredEvent, EventSeverity, EventSource


def _normalize_message(msg: str) -> str:
    msg = re.sub(r"\d{4,}", "N", msg)
    msg = re.sub(r"0x[0-9a-fA-F]+", "ADDR", msg)
    msg = re.sub(r"\d+\.\d+\.\d+\.\d+(:\d+)?", "IP", msg)
    msg = re.sub(r"[/a-zA-Z0-9_.-]+\.log", "FILE.log", msg)
    msg = re.sub(r"[a-f0-9]{8,}", "HEX", msg)
    return msg.strip()


def _template_key(source: EventSource, service: str, normalized: str) -> str:
    key = f"{source.value}:{service}:{normalized}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


class EventClusterer:
    def __init__(
        self,
        window_seconds: int = 60,
        max_clusters: int = 5000,
        merge_threshold: float = 0.85,
    ) -> None:
        self._window = window_seconds
        self._max_clusters = max_clusters
        self._merge_threshold = merge_threshold
        self._clusters: dict[str, ClusteredEvent] = {}
        self._template_map: dict[str, str] = {}

    def ingest(self, event: RawEvent) -> tuple[str, bool]:
        normalized = _normalize_message(event.message)
        template = _template_key(event.source, event.service, normalized)

        if template in self._template_map:
            cluster_id = self._template_map[template]
            cluster = self._clusters.get(cluster_id)
            if cluster:
                cluster.count += 1
                cluster.last_seen = event.timestamp
                cluster.hosts.add(event.host)
                cluster.sources.add(event.source)
                if event.severity.value > cluster.severity.value:
                    cluster.severity = event.severity
                if len(cluster.member_ids) < 100:
                    cluster.member_ids.append(event.event_id)
                return cluster_id, False

        cluster_id = f"cl-{template[:12]}"
        cluster = ClusteredEvent(
            cluster_id=cluster_id,
            template=normalized[:200],
            representative=event,
            count=1,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            hosts={event.host},
            sources={event.source},
            severity=event.severity,
            member_ids=[event.event_id],
        )

        self._clusters[cluster_id] = cluster
        self._template_map[template] = cluster_id

        self._evict_old()

        return cluster_id, True

    def ingest_batch(self, events: list[RawEvent]) -> dict[str, Any]:
        new_clusters = 0
        updated = 0
        for event in events:
            _, is_new = self.ingest(event)
            if is_new:
                new_clusters += 1
            else:
                updated += 1
        return {
            "processed": len(events),
            "new_clusters": new_clusters,
            "updated": updated,
            "total_clusters": len(self._clusters),
        }

    def get_active_clusters(
        self, min_count: int = 1, min_severity: EventSeverity | None = None
    ) -> list[ClusteredEvent]:
        now = time.time()
        results = []
        for cluster in self._clusters.values():
            if now - cluster.last_seen > self._window * 5:
                continue
            if cluster.count < min_count:
                continue
            if min_severity and cluster.severity.value < min_severity.value:
                continue
            results.append(cluster)
        return sorted(results, key=lambda c: c.count, reverse=True)

    def get_multi_host_clusters(self) -> list[ClusteredEvent]:
        return [c for c in self._clusters.values() if len(c.hosts) > 1]

    def _evict_old(self) -> None:
        if len(self._clusters) <= self._max_clusters:
            return
        sorted_clusters = sorted(self._clusters.values(), key=lambda c: c.last_seen)
        to_remove = len(self._clusters) - self._max_clusters
        for cluster in sorted_clusters[:to_remove]:
            del self._clusters[cluster.cluster_id]
            stale_keys = [
                k for k, v in self._template_map.items() if v == cluster.cluster_id
            ]
            for k in stale_keys:
                del self._template_map[k]

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "total_clusters": len(self._clusters),
            "multi_host": len(self.get_multi_host_clusters()),
        }


class CrossSourceCorrelator:
    def __init__(
        self,
        time_window_ms: float = 5000,
        same_host_boost: float = 1.5,
    ) -> None:
        self._window_ms = time_window_ms
        self._host_boost = same_host_boost

    def correlate(self, clusters: list[ClusteredEvent]) -> list[dict[str, Any]]:
        pairs: list[dict[str, Any]] = []
        sorted_clusters = sorted(clusters, key=lambda c: c.first_seen)

        for i, a in enumerate(sorted_clusters):
            for j in range(i + 1, len(sorted_clusters)):
                b = sorted_clusters[j]
                delta_ms = (b.first_seen - a.first_seen) * 1000

                if delta_ms > self._window_ms:
                    break

                if a.sources == b.sources:
                    continue

                shared_hosts = a.hosts & b.hosts
                score = 0.5

                if delta_ms < 1000:
                    score += 0.3
                elif delta_ms < 3000:
                    score += 0.15

                if shared_hosts:
                    score *= self._host_boost

                if a.sources & {EventSource.KERNEL, EventSource.EBP} and \
                   b.sources & {EventSource.APPLICATION, EventSource.CONTAINER}:
                    score += 0.2

                if score >= 0.6:
                    pairs.append({
                        "event_a": a,
                        "event_b": b,
                        "time_delta_ms": delta_ms,
                        "shared_hosts": list(shared_hosts),
                        "is_same_host": bool(shared_hosts),
                        "score": min(score, 1.0),
                        "reasoning": f"{a.sources} -> {b.sources} within {delta_ms:.0f}ms",
                    })

        return sorted(pairs, key=lambda p: p["score"], reverse=True)
