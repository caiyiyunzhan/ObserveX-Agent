from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HWError:
    source: str
    severity: str
    message: str
    timestamp: str = ""


class HWErrorCollector:
    def __init__(self, mock_data: dict[str, Any] | None = None) -> None:
        self._mock_data = mock_data

    def collect_all(self) -> list[HWError]:
        errors: list[HWError] = []
        errors.extend(self.collect_mcelog())
        errors.extend(self.collect_smartctl())
        errors.extend(self.collect_edac())
        return errors

    def collect_mcelog(self) -> list[HWError]:
        if self._mock_data is not None:
            return [
                HWError(**e) for e in self._mock_data.get("mcelog_errors", [])
            ]

        return self._run_mcelog()

    def _run_mcelog(self) -> list[HWError]:
        try:
            result = subprocess.run(
                ["mcelog", "--client"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            errors: list[HWError] = []
            for line in result.stdout.strip().splitlines():
                if line.strip():
                    errors.append(
                        HWError(
                            source="mcelog",
                            severity="critical",
                            message=line.strip(),
                        )
                    )
            return errors
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def collect_smartctl(self) -> list[HWError]:
        if self._mock_data is not None:
            return [
                HWError(**e)
                for e in self._mock_data.get("smartctl_errors", [])
            ]

        return self._run_smartctl()

    def _run_smartctl(self) -> list[HWError]:
        try:
            result = subprocess.run(
                ["smartctl", "-a", "/dev/sda"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return []

            return [
                HWError(
                    source="smartctl",
                    severity="warning",
                    message=result.stderr.strip(),
                )
            ]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def collect_edac(self) -> list[HWError]:
        if self._mock_data is not None:
            return [
                HWError(**e)
                for e in self._mock_data.get("edac_errors", [])
            ]

        return self._read_edac()

    def _read_edac(self) -> list[HWError]:
        import os
        from pathlib import Path

        errors: list[HWError] = []
        edac_base = Path("/sys/devices/system/edac/mc")

        if not edac_base.exists():
            return errors

        for mc_dir in edac_base.iterdir():
            ce_count = mc_dir / "ce_count"
            ue_count = mc_dir / "ue_count"

            if ce_count.exists():
                count = ce_count.read_text().strip()
                if int(count) > 0:
                    errors.append(
                        HWError(
                            source="edac",
                            severity="warning",
                            message=f"Correctable errors on {mc_dir.name}: {count}",
                        )
                    )

            if ue_count.exists():
                count = ue_count.read_text().strip()
                if int(count) > 0:
                    errors.append(
                        HWError(
                            source="edac",
                            severity="critical",
                            message=f"Uncorrectable errors on {mc_dir.name}: {count}",
                        )
                    )

        return errors
