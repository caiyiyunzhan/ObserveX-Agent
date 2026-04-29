from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from queue import Queue
from threading import Thread, Event
from typing import Any, Callable, Generator

from observex.models.events import RawEvent, EventSource, EventSeverity


_KMSG_PATTERN = re.compile(
    r"^\[\s*(?P<ts>[\d.]+)\]\s+(?P<msg>.+)$"
)

_JOURNALD_SEVERITY = {
    "emerg": EventSeverity.FATAL,
    "alert": EventSeverity.FATAL,
    "crit": EventSeverity.CRITICAL,
    "err": EventSeverity.ERROR,
    "warning": EventSeverity.WARNING,
    "notice": EventSeverity.INFO,
    "info": EventSeverity.INFO,
    "debug": EventSeverity.DEBUG,
}

_CONTAINER_PATTERNS = [
    re.compile(r"^.*?(?P<level>ERROR|WARN|INFO|FATAL|DEBUG)\s+(?P<msg>.+)$"),
]


def parse_kmsg(line: str, host: str = "") -> RawEvent:
    m = _KMSG_PATTERN.match(line)
    ts = float(m.group("ts")) if m else time.time()
    msg = m.group("msg") if m else line

    severity = EventSeverity.INFO
    if any(k in msg for k in ("BUG", "Oops", "panic", "RIP")):
        severity = EventSeverity.CRITICAL
    elif any(k in msg for k in ("error", "fail", "denied")):
        severity = EventSeverity.ERROR
    elif any(k in msg for k in ("warn", "deprecated")):
        severity = EventSeverity.WARNING

    return RawEvent(
        timestamp=ts,
        source=EventSource.KERNEL,
        host=host,
        severity=severity,
        message=msg,
        raw_line=line,
    )


def parse_journald_json(record: dict[str, Any], host: str = "") -> RawEvent:
    msg = record.get("MESSAGE", "")
    priority = int(record.get("PRIORITY", "6"))
    severity = _JOURNALD_SEVERITY.get(str(priority), EventSeverity.INFO)

    ts_raw = record.get("__REALTIME_TIMESTAMP", "")
    try:
        ts = int(ts_raw) / 1_000_000 if ts_raw else time.time()
    except (ValueError, TypeError):
        ts = time.time()

    service = record.get("_SYSTEMD_UNIT", record.get("SYSLOG_IDENTIFIER", ""))

    return RawEvent(
        timestamp=ts,
        source=EventSource.APPLICATION,
        host=host,
        service=service,
        severity=severity,
        message=msg,
        fields={k: v for k, v in record.items() if not k.startswith("__")},
        raw_line=str(record),
    )


def parse_container_log(line: str, host: str = "", container: str = "") -> RawEvent:
    severity = EventSeverity.INFO
    for pat in _CONTAINER_PATTERNS:
        m = pat.match(line)
        if m:
            level_str = m.group("level").upper()
            severity = {
                "FATAL": EventSeverity.FATAL,
                "ERROR": EventSeverity.ERROR,
                "WARN": EventSeverity.WARNING,
                "INFO": EventSeverity.INFO,
                "DEBUG": EventSeverity.DEBUG,
            }.get(level_str, EventSeverity.INFO)
            break

    return RawEvent(
        timestamp=time.time(),
        source=EventSource.CONTAINER,
        host=host,
        service=container,
        severity=severity,
        message=line,
        raw_line=line,
    )


def parse_ebpf_event(record: dict[str, Any], host: str = "") -> RawEvent:
    return RawEvent(
        timestamp=record.get("timestamp", time.time()),
        source=EventSource.EBP,
        host=host,
        service=record.get("function", ""),
        severity=EventSeverity.WARNING,
        message=f"eBPF: {record.get('function', '?')} pid={record.get('pid', '?')}",
        fields=record,
        raw_line=str(record),
    )


def parse_structured_log(
    data: dict[str, Any], host: str = "", source: EventSource = EventSource.APPLICATION
) -> RawEvent:
    level_str = data.get("level", data.get("severity", "INFO")).upper()
    severity = {
        "FATAL": EventSeverity.FATAL,
        "CRITICAL": EventSeverity.CRITICAL,
        "ERROR": EventSeverity.ERROR,
        "WARNING": EventSeverity.WARNING,
        "WARN": EventSeverity.WARNING,
        "INFO": EventSeverity.INFO,
        "DEBUG": EventSeverity.DEBUG,
    }.get(level_str, EventSeverity.INFO)

    ts_raw = data.get("timestamp", data.get("ts", ""))
    try:
        ts = float(ts_raw) if ts_raw else time.time()
    except (ValueError, TypeError):
        ts = time.time()

    return RawEvent(
        timestamp=ts,
        source=source,
        host=host,
        service=data.get("service", data.get("logger", "")),
        severity=severity,
        message=data.get("message", data.get("msg", str(data))),
        fields=data,
        trace_id=data.get("trace_id", data.get("traceId", "")),
        raw_line=str(data),
    )


class EventStreamProcessor:
    def __init__(
        self,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue_size: int = 100000,
    ) -> None:
        self._queue: Queue[RawEvent] = Queue(maxsize=max_queue_size)
        self._handlers: list[Callable[[list[RawEvent]], None]] = []
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._stop_event = Event()
        self._worker: Thread | None = None
        self._stats = {
            "total_received": 0,
            "total_processed": 0,
            "total_batches": 0,
            "dropped": 0,
        }

    def on_batch(self, handler: Callable[[list[RawEvent]], None]) -> None:
        self._handlers.append(handler)

    def submit(self, event: RawEvent) -> bool:
        try:
            self._queue.put_nowait(event)
            self._stats["total_received"] += 1
            return True
        except Exception:
            self._stats["dropped"] += 1
            return False

    def start(self) -> None:
        self._stop_event.clear()
        self._worker = Thread(target=self._process_loop, daemon=True)
        self._worker.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._worker:
            self._worker.join(timeout=5)

    def _process_loop(self) -> None:
        batch: list[RawEvent] = []
        last_flush = time.time()

        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.1)
                batch.append(event)
            except Exception:
                pass

            now = time.time()
            if (
                len(batch) >= self._batch_size
                or (now - last_flush) >= self._flush_interval and batch
            ):
                self._dispatch(batch)
                batch = []
                last_flush = now

        if batch:
            self._dispatch(batch)

    def _dispatch(self, batch: list[RawEvent]) -> None:
        for handler in self._handlers:
            try:
                handler(batch)
            except Exception:
                pass
        self._stats["total_processed"] += len(batch)
        self._stats["total_batches"] += 1

    @property
    def stats(self) -> dict[str, Any]:
        return {
            **self._stats,
            "queue_size": self._queue.qsize(),
        }
