from __future__ import annotations

import json
from typing import Any

from kcrash.collector.change_fetcher import ChangeFetcher
from kcrash.collector.hw_errors import HWErrorCollector
from kcrash.reasoning.prompts import PHASE2_SYSTEM, PHASE2_USER
from kcrash.reasoning.chain_panic import _call_llm
from kcrash.utils.logging import get_logger

logger = get_logger("kcrash.reasoning.history")


def phase2_history_correlation(
    panic_signature: dict[str, Any],
    change_fetcher: ChangeFetcher,
    hw_collector: HWErrorCollector,
    llm_client: Any,
    model: str = "gpt-4-turbo",
    max_tokens: int = 4096,
    hostname: str = "unknown",
    hours: int = 72,
) -> dict[str, Any]:
    changes = change_fetcher.get_recent_changes(hostname, hours)
    sibling_crashes = change_fetcher.get_sibling_crashes(hostname)
    hw_errors = hw_collector.collect_all()

    changes_text = "\n".join(
        f"  - {c.change_type}: {c.name} {c.old_version} -> {c.new_version}"
        for c in changes
    ) or "  (no changes found)"

    crashes_text = "\n".join(
        f"  - {cr.hostname}: {cr.function}+0x{cr.offset:x} ({cr.error_type}) at {cr.timestamp}"
        for cr in sibling_crashes
    ) or "  (no sibling crashes)"

    hw_text = "\n".join(
        f"  - [{e.source}] {e.severity}: {e.message}"
        for e in hw_errors
    ) or "  (no hardware errors)"

    user_prompt = PHASE2_USER.format(
        panic_signature=json.dumps(panic_signature, indent=2),
        hours=hours,
        recent_changes=changes_text,
        sibling_crashes=crashes_text,
        hw_errors=hw_text,
    )

    raw = _call_llm(llm_client, model, PHASE2_SYSTEM, user_prompt, max_tokens)

    try:
        result = _parse_phase2_response(raw)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Phase 2 LLM response as JSON")
        result = {
            "root_cause_candidates": [
                {
                    "claim": "Unable to parse LLM response",
                    "probability": 0.0,
                    "category": "unknown",
                    "evidence_chain": [raw],
                }
            ],
            "fingerprint_cluster": {"is_clustered": False, "host_count": 0, "similarity_score": 0.0},
            "recommendation": "escalate",
        }

    result["_collected_changes"] = [
        {
            "type": c.change_type,
            "name": c.name,
            "old": c.old_version,
            "new": c.new_version,
        }
        for c in changes
    ]
    result["_hw_errors"] = [
        {
            "source": e.source,
            "severity": e.severity,
            "message": e.message,
        }
        for e in hw_errors
    ]
    result["_sibling_crash_count"] = len(sibling_crashes)

    return result


def _parse_phase2_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        if lines and lines[0].startswith("json"):
            lines[0] = lines[0][4:]
        text = "\n".join(lines)
    return json.loads(text)
