from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CacheEntry:
    key: str
    value: dict[str, Any]
    created_at: float
    expires_at: float
    hit_count: int = 0


class AnalysisCache:
    def __init__(
        self,
        cache_dir: str = ".kcrash_cache",
        ttl_seconds: int = 3600,
        max_entries: int = 1000,
    ) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._index: dict[str, CacheEntry] = {}
        self._load_index()

    def _index_path(self) -> Path:
        return self._cache_dir / "index.json"

    def _load_index(self) -> None:
        idx_path = self._index_path()
        if idx_path.exists():
            try:
                with open(idx_path, "r") as f:
                    data = json.load(f)
                self._index = {
                    k: CacheEntry(**v) for k, v in data.items()
                }
            except Exception:
                self._index = {}

    def _save_index(self) -> None:
        data = {k: v.__dict__ for k, v in self._index.items()}
        with open(self._index_path(), "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def make_key(fingerprint_hash: str, model: str = "") -> str:
        raw = f"{fingerprint_hash}:{model}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def get(self, key: str) -> dict[str, Any] | None:
        entry = self._index.get(key)
        if entry is None:
            return None
        if time.time() > entry.expires_at:
            del self._index[key]
            return None

        data_path = self._cache_dir / f"{key}.json"
        if not data_path.exists():
            del self._index[key]
            return None

        entry.hit_count += 1
        with open(data_path, "r") as f:
            return json.load(f)

    def set(self, key: str, value: dict[str, Any]) -> None:
        now = time.time()

        if len(self._index) >= self._max_entries:
            self._evict_oldest()

        data_path = self._cache_dir / f"{key}.json"
        with open(data_path, "w") as f:
            json.dump(value, f, indent=2, default=str)

        self._index[key] = CacheEntry(
            key=key,
            value={},
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._save_index()

    def _evict_oldest(self) -> None:
        if not self._index:
            return
        oldest_key = min(self._index, key=lambda k: self._index[k].created_at)
        data_path = self._cache_dir / f"{oldest_key}.json"
        data_path.unlink(missing_ok=True)
        del self._index[oldest_key]

    def clear(self) -> None:
        for entry in self._index.values():
            data_path = self._cache_dir / f"{entry.key}.json"
            data_path.unlink(missing_ok=True)
        self._index.clear()
        self._save_index()

    @property
    def stats(self) -> dict[str, Any]:
        total_hits = sum(e.hit_count for e in self._index.values())
        return {
            "entries": len(self._index),
            "total_hits": total_hits,
            "ttl_seconds": self._ttl,
        }
