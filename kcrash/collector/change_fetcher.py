from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Change:
    change_type: str
    name: str
    old_version: str
    new_version: str


@dataclass
class CrashRecord:
    hostname: str
    function: str
    offset: int
    error_type: str
    timestamp: str


class ChangeFetcher:
    def __init__(self, mock_data: dict[str, Any] | None = None) -> None:
        self._mock_data = mock_data

    def get_recent_changes(
        self, hostname: str, hours: int = 72
    ) -> list[Change]:
        if self._mock_data is not None:
            return [
                Change(
                    change_type=c["type"],
                    name=c["name"],
                    old_version=c["old"],
                    new_version=c["new"],
                )
                for c in self._mock_data.get("recent_changes", [])
            ]

        return self._fetch_from_cmdb(hostname, hours)

    def _fetch_from_cmdb(self, hostname: str, hours: int) -> list[Change]:
        return [
            Change(
                change_type="rpm",
                name="kernel",
                old_version="5.14.0-284.el9",
                new_version="5.14.0-285.el9",
            ),
            Change(
                change_type="config",
                name="sysctl/net.core.somaxconn",
                old_version="128",
                new_version="4096",
            ),
        ]

    def get_sibling_crashes(
        self, host_pattern: str, months: int = 6
    ) -> list[CrashRecord]:
        if self._mock_data is not None:
            return [
                CrashRecord(**r)
                for r in self._mock_data.get("sibling_crashes", [])
            ]

        return self._query_crash_db(host_pattern, months)

    def _query_crash_db(
        self, host_pattern: str, months: int
    ) -> list[CrashRecord]:
        return []
