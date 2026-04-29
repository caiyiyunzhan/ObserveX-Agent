from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import urllib.request
import urllib.error

from kcrash.notifications.base import NotificationChannel
from kcrash.core.severity import Severity
from kcrash.utils.logging import get_logger
from kcrash.exceptions import NotificationError

logger = get_logger("kcrash.notifications")


@dataclass
class NotificationResult:
    channel: str
    success: bool
    error: str = ""
    latency_ms: float = 0.0


class WebhookChannel(NotificationChannel):
    name = "webhook"

    def __init__(
        self,
        url: str,
        timeout: float = 10.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._url = url
        self._timeout = timeout
        self._headers = headers or {"Content-Type": "application/json"}

    def send(self, subject: str, body: str, metadata: dict | None = None) -> bool:
        payload = {
            "subject": subject,
            "body": body,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        try:
            data = json.dumps(payload, default=str).encode("utf-8")
            req = urllib.request.Request(
                self._url, data=data, headers=self._headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.status < 400
        except Exception as exc:
            logger.error("Webhook send failed: %s", exc)
            return False

    def health_check(self) -> bool:
        try:
            req = urllib.request.Request(self._url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status < 400
        except Exception:
            return False


_LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class LogChannel(NotificationChannel):
    name = "log"

    def send(self, subject: str, body: str, metadata: dict | None = None) -> bool:
        level_name = (metadata.get("severity", "INFO") if metadata else "INFO").upper()
        level = _LEVEL_MAP.get(level_name, logging.INFO)
        logger.log(level, "[NOTIFY] %s: %s", subject, body)
        return True

    def health_check(self) -> bool:
        return True


class ConsoleChannel(NotificationChannel):
    name = "console"

    def send(self, subject: str, body: str, metadata: dict | None = None) -> bool:
        severity = metadata.get("severity", "INFO") if metadata else "INFO"
        print(f"[{severity}] {subject}: {body}")
        return True

    def health_check(self) -> bool:
        return True


class NotificationManager:
    def __init__(self) -> None:
        self._channels: list[NotificationChannel] = []
        self._rules: list[dict[str, Any]] = []

    def add_channel(self, channel: NotificationChannel) -> None:
        self._channels.append(channel)

    def add_rule(
        self,
        min_severity: Severity | None = None,
        fingerprint_pattern: str = "",
        channels: list[str] | None = None,
    ) -> None:
        self._rules.append({
            "min_severity": min_severity,
            "fingerprint_pattern": fingerprint_pattern,
            "channels": channels,
        })

    def notify(
        self,
        crash_id: str,
        root_cause: str,
        severity: Severity,
        confidence: float,
        fingerprint_hash: str = "",
        patch_available: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> list[NotificationResult]:
        if not self._channels:
            return []

        subject = f"[kcrash-{severity.label()}] Crash {crash_id}"
        body_lines = [
            f"Root Cause: {root_cause}",
            f"Confidence: {confidence:.2f}",
            f"Severity: {severity.label()}",
            f"Fingerprint: {fingerprint_hash}",
        ]
        if patch_available:
            body_lines.append("Hot-patch: AVAILABLE")
        body = "\n".join(body_lines)

        metadata = {
            "severity": severity.label(),
            "crash_id": crash_id,
            "confidence": confidence,
            "fingerprint": fingerprint_hash,
            **(extra or {}),
        }

        target_channels = self._resolve_channels(severity, fingerprint_hash)

        results: list[NotificationResult] = []
        for channel in target_channels:
            start = time.time()
            try:
                ok = channel.send(subject, body, metadata)
                latency = (time.time() - start) * 1000
                results.append(
                    NotificationResult(
                        channel=channel.name, success=ok, latency_ms=latency
                    )
                )
            except Exception as exc:
                latency = (time.time() - start) * 1000
                results.append(
                    NotificationResult(
                        channel=channel.name,
                        success=False,
                        error=str(exc),
                        latency_ms=latency,
                    )
                )

        return results

    def _resolve_channels(
        self, severity: Severity, fingerprint: str
    ) -> list[NotificationChannel]:
        if not self._rules:
            return self._channels

        matched: set[str] = set()
        for rule in self._rules:
            if rule["min_severity"] and severity < rule["min_severity"]:
                continue
            if rule["fingerprint_pattern"] and rule["fingerprint_pattern"] not in fingerprint:
                continue
            if rule["channels"]:
                matched.update(rule["channels"])

        if not matched:
            return self._channels

        return [c for c in self._channels if c.name in matched]

    def health_check(self) -> dict[str, bool]:
        return {ch.name: ch.health_check() for ch in self._channels}
