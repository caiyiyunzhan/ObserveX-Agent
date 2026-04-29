from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from kcrash.exceptions import LLMError


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerStats:
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    rejected_calls: int = 0
    last_failure_time: float = 0.0
    last_success_time: float = 0.0


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 3,
        name: str = "default",
    ) -> None:
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max = half_open_max_calls
        self._name = name
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0
        self._stats = CircuitBreakerStats()
        self._lock = threading.Lock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._stats.last_failure_time >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
            return self._state

    @property
    def stats(self) -> CircuitBreakerStats:
        return self._stats

    def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            self._stats.total_calls += 1

            current_state = self._state
            if current_state == CircuitState.OPEN:
                if time.time() - self._stats.last_failure_time >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    current_state = CircuitState.HALF_OPEN

            if current_state == CircuitState.OPEN:
                self._stats.rejected_calls += 1
                raise LLMError(
                    f"Circuit breaker '{self._name}' is OPEN",
                    details={
                        "state": "open",
                        "failures": self._failure_count,
                        "recovery_in": max(
                            0, self._recovery_timeout - (time.time() - self._stats.last_failure_time)
                        ),
                    },
                )

            if current_state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self._half_open_max:
                    self._stats.rejected_calls += 1
                    raise LLMError(
                        f"Circuit breaker '{self._name}' half-open limit reached"
                    )
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            with self._lock:
                self._stats.successful_calls += 1
                self._stats.last_success_time = time.time()
                self._failure_count = 0
                self._state = CircuitState.CLOSED
            return result
        except Exception as exc:
            with self._lock:
                self._stats.failed_calls += 1
                self._stats.last_failure_time = time.time()
                self._failure_count += 1
                if self._failure_count >= self._failure_threshold:
                    self._state = CircuitState.OPEN
                elif self._state == CircuitState.HALF_OPEN:
                    self._state = CircuitState.OPEN
            raise

    def reset(self) -> None:
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._half_open_calls = 0
            self._stats = CircuitBreakerStats()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self._name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "recovery_timeout": self._recovery_timeout,
            "stats": {
                "total_calls": self._stats.total_calls,
                "successful_calls": self._stats.successful_calls,
                "failed_calls": self._stats.failed_calls,
                "rejected_calls": self._stats.rejected_calls,
            },
        }
