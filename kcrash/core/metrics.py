from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Counter:
    value: float = 0.0

    def inc(self, amount: float = 1.0) -> None:
        self.value += amount


@dataclass
class Gauge:
    value: float = 0.0

    def set(self, value: float) -> None:
        self.value = value

    def inc(self, amount: float = 1.0) -> None:
        self.value += amount

    def dec(self, amount: float = 1.0) -> None:
        self.value -= amount


@dataclass
class Histogram:
    buckets: list[float] = field(default_factory=lambda: [
        100, 500, 1000, 5000, 10000, 30000, 60000, 120000, 300000
    ])
    counts: list[int] = field(default_factory=list)
    total_count: int = 0
    total_sum: float = 0.0

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = [0] * (len(self.buckets) + 1)

    def observe(self, value: float) -> None:
        self.total_count += 1
        self.total_sum += value
        for i, bound in enumerate(self.buckets):
            if value <= bound:
                self.counts[i] += 1
                return
        self.counts[-1] += 1

    @property
    def avg(self) -> float:
        if self.total_count == 0:
            return 0.0
        return self.total_sum / self.total_count


@dataclass
class Summary:
    values: list[float] = field(default_factory=list)
    max_size: int = 1000

    def observe(self, value: float) -> None:
        self.values.append(value)
        if len(self.values) > self.max_size:
            self.values = self.values[-self.max_size:]

    def percentile(self, p: float) -> float:
        if not self.values:
            return 0.0
        sorted_vals = sorted(self.values)
        idx = int(len(sorted_vals) * p / 100.0)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    @property
    def avg(self) -> float:
        if not self.values:
            return 0.0
        return sum(self.values) / len(self.values)


class MetricsCollector:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._histograms: dict[str, Histogram] = {}
        self._summaries: dict[str, Summary] = {}
        self._labels: dict[str, dict[str, str]] = {}

    def _make_key(self, name: str, labels: dict[str, str] | None = None) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def counter(self, name: str, labels: dict[str, str] | None = None) -> Counter:
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._counters:
                self._counters[key] = Counter()
                if labels:
                    self._labels[key] = labels
            return self._counters[key]

    def gauge(self, name: str, labels: dict[str, str] | None = None) -> Gauge:
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._gauges:
                self._gauges[key] = Gauge()
                if labels:
                    self._labels[key] = labels
            return self._gauges[key]

    def histogram(
        self, name: str, labels: dict[str, str] | None = None
    ) -> Histogram:
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._histograms:
                self._histograms[key] = Histogram()
                if labels:
                    self._labels[key] = labels
            return self._histograms[key]

    def summary(self, name: str, labels: dict[str, str] | None = None) -> Summary:
        key = self._make_key(name, labels)
        with self._lock:
            if key not in self._summaries:
                self._summaries[key] = Summary()
                if labels:
                    self._labels[key] = labels
            return self._summaries[key]

    def export(self) -> dict[str, Any]:
        with self._lock:
            result: dict[str, Any] = {"counters": {}, "gauges": {}, "histograms": {}, "summaries": {}}

            for key, c in self._counters.items():
                result["counters"][key] = c.value

            for key, g in self._gauges.items():
                result["gauges"][key] = g.value

            for key, h in self._histograms.items():
                result["histograms"][key] = {
                    "count": h.total_count,
                    "sum": h.total_sum,
                    "avg": h.avg,
                    "buckets": dict(zip(
                        [str(b) for b in h.buckets] + ["+Inf"],
                        h.counts,
                    )),
                }

            for key, s in self._summaries.items():
                result["summaries"][key] = {
                    "count": len(s.values),
                    "avg": s.avg,
                    "p50": s.percentile(50),
                    "p90": s.percentile(90),
                    "p95": s.percentile(95),
                    "p99": s.percentile(99),
                }

            return result

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()
            self._summaries.clear()
            self._labels.clear()


_global_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    return _global_metrics
