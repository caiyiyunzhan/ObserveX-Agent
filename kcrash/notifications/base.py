from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class NotificationChannel(ABC):
    name: str

    @abstractmethod
    def send(self, subject: str, body: str, metadata: dict[str, Any] | None = None) -> bool:
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> bool:
        raise NotImplementedError
