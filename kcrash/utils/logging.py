from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        for key in ("component", "crash_id", "host", "duration_ms", "tokens"):
            val = getattr(record, key, None)
            if val is not None:
                entry[key] = val
        return json.dumps(entry, ensure_ascii=False)


def get_logger(
    name: str, level: int = logging.INFO
) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


def log_call(
    logger: logging.Logger,
    component: str,
    crash_id: str = "",
    **extra: Any,
) -> logging.LoggerAdapter:
    return logging.LoggerAdapter(
        logger, {"component": component, "crash_id": crash_id, **extra}
    )
