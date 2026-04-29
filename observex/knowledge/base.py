from __future__ import annotations

import json
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FailurePattern:
    pattern_id: str = ""
    name: str = ""
    description: str = ""
    signature: list[str] = field(default_factory=list)
    root_cause_category: str = ""
    remediation_hints: list[str] = field(default_factory=list)
    occurrence_count: int = 0
    last_seen: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "signature": self.signature,
            "category": self.root_cause_category,
            "remediation": self.remediation_hints,
            "count": self.occurrence_count,
            "confidence": self.confidence,
        }


@dataclass
class KnowledgeEntry:
    entry_id: str = ""
    entry_type: str = ""
    title: str = ""
    content: str = ""
    source_incidents: list[str] = field(default_factory=list)
    created_at: float = 0.0
    updated_at: float = 0.0
    tags: list[str] = field(default_factory=list)


class KnowledgeBase:
    def __init__(self, kb_dir: str = ".observex_kb") -> None:
        self._kb_dir = Path(kb_dir)
        self._kb_dir.mkdir(parents=True, exist_ok=True)
        self._patterns: dict[str, FailurePattern] = {}
        self._entries: dict[str, KnowledgeEntry] = {}
        self._load()

    def _patterns_path(self) -> Path:
        return self._kb_dir / "patterns.json"

    def _entries_path(self) -> Path:
        return self._kb_dir / "entries.json"

    def _load(self) -> None:
        p = self._patterns_path()
        if p.exists():
            with open(p, "r") as f:
                data = json.load(f)
            self._patterns = {k: FailurePattern(**v) for k, v in data.items()}

        e = self._entries_path()
        if e.exists():
            with open(e, "r") as f:
                data = json.load(f)
            self._entries = {k: KnowledgeEntry(**v) for k, v in data.items()}

    def _save(self) -> None:
        with open(self._patterns_path(), "w") as f:
            json.dump({k: v.to_dict() for k, v in self._patterns.items()}, f, indent=2)
        data = {k: vars(v) for k, v in self._entries.items()}
        with open(self._entries_path(), "w") as f:
            json.dump(data, f, indent=2, default=str)

    def add_pattern(self, pattern: FailurePattern) -> str:
        if not pattern.pattern_id:
            sig_str = json.dumps(pattern.signature, sort_keys=True)
            pattern.pattern_id = hashlib.sha256(sig_str.encode()).hexdigest()[:12]

        existing = self._patterns.get(pattern.pattern_id)
        if existing:
            existing.occurrence_count += 1
            existing.last_seen = time.time()
            existing.confidence = min(existing.confidence + 0.05, 1.0)
        else:
            pattern.occurrence_count = 1
            pattern.last_seen = time.time()
            self._patterns[pattern.pattern_id] = pattern

        self._save()
        return pattern.pattern_id

    def match_pattern(self, signature: list[str], threshold: float = 0.5) -> list[FailurePattern]:
        sig_set = set(signature)
        matches: list[tuple[float, FailurePattern]] = []

        for pattern in self._patterns.values():
            pat_set = set(pattern.signature)
            if not sig_set or not pat_set:
                continue
            intersection = len(sig_set & pat_set)
            union = len(sig_set | pat_set)
            jaccard = intersection / union if union > 0 else 0
            if jaccard >= threshold:
                matches.append((jaccard, pattern))

        return [p for _, p in sorted(matches, key=lambda x: x[0], reverse=True)]

    def add_entry(self, entry: KnowledgeEntry) -> str:
        if not entry.entry_id:
            entry.entry_id = hashlib.sha256(entry.content.encode()).hexdigest()[:12]
        entry.updated_at = time.time()
        self._entries[entry.entry_id] = entry
        self._save()
        return entry.entry_id

    def search_entries(self, query: str, limit: int = 10) -> list[KnowledgeEntry]:
        query_lower = query.lower()
        results = []
        for entry in self._entries.values():
            if (
                query_lower in entry.title.lower()
                or query_lower in entry.content.lower()
                or any(query_lower in tag.lower() for tag in entry.tags)
            ):
                results.append(entry)
        return results[:limit]

    def summarize_patterns(self) -> dict[str, Any]:
        categories: dict[str, list[FailurePattern]] = {}
        for p in self._patterns.values():
            categories.setdefault(p.root_cause_category, []).append(p)

        return {
            "total_patterns": len(self._patterns),
            "total_entries": len(self._entries),
            "categories": {
                cat: {
                    "count": len(patterns),
                    "top_patterns": [
                        {"name": p.name, "count": p.occurrence_count}
                        for p in sorted(patterns, key=lambda x: x.occurrence_count, reverse=True)[:5]
                    ],
                }
                for cat, patterns in categories.items()
            },
        }

    def learn_from_incident(
        self,
        incident_id: str,
        root_cause: str,
        resolution: str,
        signature: list[str],
        category: str = "",
    ) -> str:
        pattern = FailurePattern(
            name=f"Pattern from {incident_id}",
            description=root_cause[:500],
            signature=signature,
            root_cause_category=category or "uncategorized",
            remediation_hints=[resolution[:500]] if resolution else [],
        )
        pid = self.add_pattern(pattern)

        entry = KnowledgeEntry(
            entry_type="incident_resolution",
            title=f"Resolution for {incident_id}",
            content=f"Root cause: {root_cause}\nResolution: {resolution}",
            source_incidents=[incident_id],
            tags=[category] if category else [],
            created_at=time.time(),
        )
        self.add_entry(entry)

        return pid

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "patterns": len(self._patterns),
            "entries": len(self._entries),
        }
