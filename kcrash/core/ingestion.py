from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Generator

from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.ingestion")


@dataclass
class CrashEvent:
    vmcore_path: str
    vmlinux_path: str
    hostname: str
    crash_id: str
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CrashIngestion:
    def __init__(
        self,
        watch_dir: str | None = None,
        vmlinux_dir: str = "/usr/lib/debug/lib/modules",
    ) -> None:
        self._watch_dir = Path(watch_dir) if watch_dir else None
        self._vmlinux_dir = Path(vmlinux_dir)
        self._handlers: list[Callable[[CrashEvent], None]] = []

    def on_crash(self, handler: Callable[[CrashEvent], None]) -> None:
        self._handlers.append(handler)

    def ingest_single(self, vmcore_path: str, hostname: str = "unknown") -> CrashEvent:
        vmcore = Path(vmcore_path)
        if not vmcore.exists():
            raise FileNotFoundError(f"vmcore not found: {vmcore_path}")

        vmlinux = self._resolve_vmlinux(vmcore)
        crash_id = f"crash-{hostname}-{int(time.time())}"

        event = CrashEvent(
            vmcore_path=str(vmcore),
            vmlinux_path=str(vmlinux),
            hostname=hostname,
            crash_id=crash_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            metadata={
                "file_size": vmcore.stat().st_size,
                "file_name": vmcore.name,
            },
        )

        logger.info(
            "Ingested crash: %s from %s", crash_id, hostname,
            extra={"crash_id": crash_id},
        )

        for handler in self._handlers:
            try:
                handler(event)
            except Exception as exc:
                logger.error("Handler failed for %s: %s", crash_id, exc)

        return event

    def ingest_batch(
        self, manifest_path: str
    ) -> Generator[CrashEvent, None, None]:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        for entry in manifest.get("crashes", []):
            try:
                event = self.ingest_single(
                    vmcore_path=entry["vmcore"],
                    hostname=entry.get("hostname", "unknown"),
                )
                yield event
            except Exception as exc:
                logger.error("Failed to ingest %s: %s", entry.get("vmcore"), exc)

    def _resolve_vmlinux(self, vmcore: Path) -> Path:
        if vmcore.suffix == ".json":
            return Path("dummy")

        release = self._extract_release(vmcore)
        if release:
            candidate = self._vmlinux_dir / release / "vmlinux"
            if candidate.exists():
                return candidate

        return Path("/usr/lib/debug/lib/modules/vmlinux")

    def _extract_release(self, vmcore: Path) -> str | None:
        return None


class CrashWatcher:
    def __init__(
        self,
        watch_dir: str,
        vmlinux_dir: str = "/usr/lib/debug/lib/modules",
        poll_interval: float = 5.0,
    ) -> None:
        self._watch_dir = Path(watch_dir)
        self._ingestion = CrashIngestion(
            watch_dir=watch_dir, vmlinux_dir=vmlinux_dir
        )
        self._poll_interval = poll_interval
        self._seen: set[str] = set()

    def watch(self) -> Generator[CrashEvent, None, None]:
        logger.info("Watching directory: %s", self._watch_dir)

        while True:
            for path in sorted(self._watch_dir.iterdir()):
                if path.suffix in (".vmcore", ".kdump", ".core") or path.name == "vmcore":
                    if str(path) not in self._seen:
                        self._seen.add(str(path))
                        try:
                            event = self._ingestion.ingest_single(str(path))
                            yield event
                        except Exception as exc:
                            logger.error("Failed to ingest %s: %s", path, exc)

            time.sleep(self._poll_interval)
