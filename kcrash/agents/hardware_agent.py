from __future__ import annotations

from typing import Any

from kcrash.agents.base_agent import Argument, BaseAgent


class HardwareAgent(BaseAgent):
    name = "HardwareAgent"

    def initial_argument(self, context: dict[str, Any]) -> Argument:
        hw_errors = context.get("_hw_errors", [])

        critical_errors = [
            e for e in hw_errors if e.get("severity") == "critical"
        ]
        warning_errors = [
            e for e in hw_errors if e.get("severity") == "warning"
        ]

        if critical_errors:
            claim = "Root cause is likely hardware failure"
            confidence = 0.8
            evidences = [
                f"Critical: [{e['source']}] {e['message']}"
                for e in critical_errors
            ]
        elif warning_errors:
            claim = (
                "Hardware degradation detected, may be contributing factor"
            )
            confidence = 0.4
            evidences = [
                f"Warning: [{e['source']}] {e['message']}"
                for e in warning_errors
            ]
        else:
            claim = "No hardware errors detected"
            confidence = 0.1
            evidences = ["mcelog, smartctl, and EDAC show no errors"]

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=confidence,
            evidences=evidences,
        )

    def rebut(
        self, opponent_arguments: list[Argument], context: dict[str, Any]
    ) -> Argument:
        hw_errors = context.get("_hw_errors", [])
        critical_errors = [
            e for e in hw_errors if e.get("severity") == "critical"
        ]

        change_based = any(
            "change" in arg.claim.lower() or "module" in arg.claim.lower()
            for arg in opponent_arguments
            if arg.agent_name != self.name
        )

        if critical_errors:
            confidence = 0.7 if change_based else 0.8
            claim = (
                "Hardware errors exist and may interact with kernel changes, "
                "but standalone hardware failure remains possible"
                if change_based
                else "Root cause is hardware failure based on critical errors"
            )
            evidences = [
                f"Critical HW error: [{e['source']}] {e['message']}"
                for e in critical_errors
            ]
        else:
            confidence = 0.15
            claim = (
                "No strong hardware evidence; "
                "acknowledge software-based hypotheses may be correct"
            )
            evidences = [
                "No critical hardware errors found",
                "Software causes appear more likely given available data",
            ]

        return Argument(
            agent_name=self.name,
            claim=claim,
            confidence=confidence,
            evidences=evidences,
        )
